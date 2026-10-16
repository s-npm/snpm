/**
 * Bounded-concurrency source fetch (SPEC 17.4).
 *
 * One slow package must not serialize the whole closure, but unbounded
 * parallelism exhausts file descriptors and memory on small machines — so
 * downloads stream through a fixed-size worker pool while results stay in
 * deterministic key order. Every request settles before the outcome is
 * decided; when several fail, the smallest key's failure is reported so
 * diagnostics are reproducible and never depend on completion order.
 */

import { SnpmError, toSnpmError } from "../errors.ts";
import { Store } from "../store/layout.ts";
import { Transaction } from "../store/txn.ts";
import type { StoreDb } from "../store/db.ts";
import type { Logger } from "../log.ts";
import {
  fetchAndCommitSource,
  type FetchedSource,
  type FetchSourceOptions,
} from "./package.ts";
import type { RegistryClient } from "./registry.ts";

export const DEFAULT_FETCH_CONCURRENCY = 8;

export type SourceFetchRequest = {
  /** Deterministic identity used for ordering and error selection. */
  key: string;
  name: string;
  version: string;
};

export type FetchSourcesOptions = {
  store: Store;
  registry: RegistryClient;
  txn: Transaction;
  requests: SourceFetchRequest[];
  /** Worker count; defaults to 8, always at least 1. */
  concurrency?: number;
  db?: StoreDb;
  logger?: Logger;
  limits?: FetchSourceOptions["limits"];
  allowWeakIntegrity?: boolean;
  keepTarball?: boolean;
  fetchOne?: (
    request: SourceFetchRequest,
    context: {
      store: Store;
      registry: RegistryClient;
      txn: Transaction;
      db?: StoreDb;
      logger?: Logger;
      limits?: FetchSourceOptions["limits"];
      allowWeakIntegrity?: boolean;
      keepTarball?: boolean;
    },
  ) => Promise<FetchedSource>;
};

async function defaultFetchOne(
  request: SourceFetchRequest,
  context: {
    store: Store;
    registry: RegistryClient;
    txn: Transaction;
    db?: StoreDb;
    logger?: Logger;
    limits?: FetchSourceOptions["limits"];
    allowWeakIntegrity?: boolean;
    keepTarball?: boolean;
  },
): Promise<FetchedSource> {
  return fetchAndCommitSource({
    store: context.store,
    registry: context.registry,
    txn: context.txn,
    name: request.name,
    version: request.version,
    ...(context.db === undefined ? {} : { db: context.db }),
    ...(context.logger === undefined ? {} : { logger: context.logger }),
    ...(context.limits === undefined ? {} : { limits: context.limits }),
    ...(context.allowWeakIntegrity === undefined
      ? {}
      : { allowWeakIntegrity: context.allowWeakIntegrity }),
    ...(context.keepTarball === undefined
      ? {}
      : { keepTarball: context.keepTarball }),
  });
}

export async function fetchSources(
  options: FetchSourcesOptions,
): Promise<Map<string, FetchedSource>> {
  const sorted = [...options.requests].sort((a, b) =>
    compareStrings(a.key, b.key),
  );
  const workers = Math.max(
    1,
    Math.floor(options.concurrency ?? DEFAULT_FETCH_CONCURRENCY),
  );
  const fetchOne = options.fetchOne ?? defaultFetchOne;
  const context = {
    store: options.store,
    registry: options.registry,
    txn: options.txn,
    ...(options.db === undefined ? {} : { db: options.db }),
    ...(options.logger === undefined ? {} : { logger: options.logger }),
    ...(options.limits === undefined ? {} : { limits: options.limits }),
    ...(options.allowWeakIntegrity === undefined
      ? {}
      : { allowWeakIntegrity: options.allowWeakIntegrity }),
    ...(options.keepTarball === undefined
      ? {}
      : { keepTarball: options.keepTarball }),
  };

  const results = new Array<FetchedSource | undefined>(sorted.length);
  const failures = new Array<{ key: string; error: SnpmError } | undefined>(
    sorted.length,
  );
  let next = 0;
  const runWorker = async (): Promise<void> => {
    for (;;) {
      const index = next;
      next += 1;
      const request = sorted[index];
      if (request === undefined) return;
      try {
        results[index] = await fetchOne(request, context);
      } catch (error) {
        failures[index] = {
          key: request.key,
          error: toSnpmError(error, `failed to fetch ${request.key}`),
        };
      }
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(workers, sorted.length) }, () => runWorker()),
  );

  let selected: { key: string; error: SnpmError } | undefined;
  for (const failure of failures) {
    if (failure === undefined) continue;
    if (
      selected === undefined ||
      compareStrings(failure.key, selected.key) < 0
    ) {
      selected = failure;
    }
  }
  if (selected !== undefined) throw selected.error;

  const ordered = new Map<string, FetchedSource>();
  for (const [index, request] of sorted.entries()) {
    const result = results[index];
    if (result === undefined) {
      throw new SnpmError(
        "SNPM_INTERNAL",
        `fetch produced no result for ${request.key}`,
        {
          detail: { key: request.key },
        },
      );
    }
    ordered.set(request.key, result);
  }
  return ordered;
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
