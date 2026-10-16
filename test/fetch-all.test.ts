import { mkdtemp, rm } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SnpmError } from "../src/errors.ts";
import { fetchSources } from "../src/fetch/all.ts";
import type { FetchedSource } from "../src/fetch/package.ts";
import { RegistryClient } from "../src/fetch/registry.ts";
import { Store } from "../src/store/layout.ts";
import { Transaction } from "../src/store/txn.ts";

let root: string;
let store: Store;
let registry: RegistryClient;
let txn: Transaction;

beforeEach(async () => {
  root = await mkdtemp(path.join(os.tmpdir(), "snpm-fetch-all-"));
  store = await Store.open({ root: path.join(root, "store"), create: true });
  registry = new RegistryClient({
    registry: "https://registry.example.com/",
    userAgent: "test",
  });
  txn = await Transaction.begin(store, "test");
});

afterEach(async () => {
  await txn.finish().catch(() => {});
  await rm(root, { recursive: true, force: true });
});

function fakeSource(key: string): FetchedSource {
  return {
    sourceId: `src1_${key}`,
    manifestHash: "hash",
    created: true,
    fileCount: 1,
    entryCount: 1,
    logicalBytes: 1,
    name: key,
    version: "1.0.0",
    origin: "https://registry.example.com",
    integrity: "sha512-x",
    archiveBytes: 1,
    weakIntegrity: false,
    deprecated: undefined,
  };
}

const delay = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

describe("fetchSources", () => {
  it("fetches every request with bounded concurrency", async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const seen: string[] = [];
    const result = await fetchSources({
      store,
      registry,
      txn,
      requests: ["d", "b", "a", "c", "e"].map((key) => ({
        key,
        name: key,
        version: "1.0.0",
      })),
      concurrency: 2,
      fetchOne: async (request) => {
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await delay(20);
        inFlight -= 1;
        seen.push(request.key);
        return fakeSource(request.key);
      },
    });

    expect(maxInFlight).toBeLessThanOrEqual(2);
    expect(maxInFlight).toBeGreaterThan(1);
    expect([...result.keys()]).toEqual(["a", "b", "c", "d", "e"]);
    expect(seen.sort()).toEqual(["a", "b", "c", "d", "e"]);
  });

  it("reports the smallest failing key deterministically", async () => {
    const failure = await fetchSources({
      store,
      registry,
      txn,
      requests: ["c", "a", "b"].map((key) => ({
        key,
        name: key,
        version: "1.0.0",
      })),
      concurrency: 3,
      fetchOne: async (request) => {
        await delay(request.key === "a" ? 30 : 5);
        if (request.key === "a" || request.key === "b") {
          throw new SnpmError("SNPM_FETCH_FAILED", `nope ${request.key}`, {
            detail: { key: request.key },
          });
        }
        return fakeSource(request.key);
      },
    }).then(
      () => null,
      (error: unknown) => error,
    );
    expect(failure).toMatchObject({ code: "SNPM_FETCH_FAILED" });
    expect(failure).toMatchObject({
      detail: expect.objectContaining({ key: "a" }),
    });
  });

  it("wraps non-snpm failures without losing them", async () => {
    const failure = await fetchSources({
      store,
      registry,
      txn,
      requests: [{ key: "a", name: "a", version: "1.0.0" }],
      fetchOne: async () => {
        throw new Error("boom");
      },
    }).then(
      () => null,
      (error: unknown) => error,
    );
    expect(failure).toMatchObject({ code: "SNPM_INTERNAL" });
  });

  it("handles empty requests and serial execution", async () => {
    expect(
      (await fetchSources({ store, registry, txn, requests: [] })).size,
    ).toBe(0);
    const result = await fetchSources({
      store,
      registry,
      txn,
      requests: [{ key: "only", name: "only", version: "1.0.0" }],
      concurrency: 1,
      fetchOne: async (request) => fakeSource(request.key),
    });
    expect([...result.keys()]).toEqual(["only"]);
  });
});
