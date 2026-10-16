/**
 * Temporary tool environments: `snpm dlx <spec> [args...]` (SPEC 22.4).
 *
 * A tool specifier resolves to an exact package identity; its closure is
 * fetched, verified, and realized through the shared store (reused across
 * runs by exact graph identity, never a mutable `latest`); the tool binary
 * runs with inherited stdio in an isolated task directory outside the
 * store; the directory is removed afterwards. The running process is the
 * lease: nothing else can collect the environment mid-run, and cleanup
 * never touches a running tool.
 *
 * Trust policy is honored strictly: dependency lifecycle scripts are denied
 * by default, and no script runner exists yet, so any tool closure
 * declaring install-time scripts fails with SNPM_SCRIPT_BLOCKED instead of
 * running anything.
 */

import { spawn } from "node:child_process";
import { lstat, mkdtemp, readFile } from "node:fs/promises";
import npa from "npm-package-arg";
import * as os from "node:os";
import * as path from "node:path";
import { SnpmError } from "../errors.ts";
import { fetchSources } from "../fetch/all.ts";
import type { RegistryClient } from "../fetch/registry.ts";
import type { Logger } from "../log.ts";
import { installProjection } from "../project/projection.ts";
import { createGraphDoc } from "../store/graph.ts";
import type { Store } from "../store/layout.ts";
import { packageDirIn, realizeGraph } from "../store/realize.ts";
import {
  resolveRequirements,
  type ResolvedOccurrence,
} from "../resolve/resolver.ts";
import { Transaction } from "../store/txn.ts";
import { rmrfNoFollow } from "../util/fsx.ts";
import { closeCode } from "../util/proc.ts";

export type DlxOptions = {
  store: Store;
  registry: RegistryClient;
  /** Tool specifier: name[@version|range|tag], possibly an npm alias. */
  spec: string;
  /** Arguments forwarded to the tool binary. */
  args?: readonly string[];
  /** Working directory for the tool (default: current directory). */
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  /** Explicit bin name; otherwise auto-selected (single or package-named). */
  binName?: string;
  /** Capture stdio instead of inheriting it (used by tests). */
  capture?: boolean;
  logger?: Logger;
};

export type DlxResult = {
  exitCode: number;
  key: string;
  name: string;
  version: string;
  /** True when every needed realization already existed. */
  reused: boolean;
  stdout: string;
  stderr: string;
  /** Removed temp environment path (assertable, always deleted). */
  envDir: string;
};

/** Split a tool specifier into its edge name and version part. */
export function splitDlxSpec(spec: string): {
  name: string;
  versionSpec: string;
} {
  const invalid = (cause?: unknown): SnpmError =>
    new SnpmError(
      "SNPM_RESOLUTION_FAILED",
      `invalid tool specifier "${spec}"`,
      {
        detail: { spec },
        remedy: "use a package name with an optional @version, @range, or @tag",
        ...(cause === undefined ? {} : { cause }),
      },
    );
  let parsed: { name: unknown };
  try {
    parsed = npa(spec);
  } catch (error) {
    throw invalid(error);
  }
  if (typeof parsed.name !== "string" || parsed.name === "") throw invalid();
  if (spec === parsed.name) return { name: parsed.name, versionSpec: "" };
  if (!spec.startsWith(`${parsed.name}@`)) throw invalid();
  return { name: parsed.name, versionSpec: spec.slice(parsed.name.length + 1) };
}

export async function runDlx(options: DlxOptions): Promise<DlxResult> {
  const { store, registry } = options;
  const args = options.args ?? [];
  const cwd = options.cwd ?? process.cwd();
  const env = options.env ?? process.env;

  const split = splitDlxSpec(options.spec);
  const resolved = await resolveRequirements({
    provider: registry,
    requirements: [{ name: split.name, spec: split.versionSpec }],
  });
  const root = resolved.roots.find((entry) => entry.name === split.name);
  if (root === undefined)
    throw internal(`resolution lost the root for "${options.spec}"`);
  const byKey = new Map(resolved.nodes.map((node) => [node.key, node]));
  const tool = byKey.get(root.target);
  if (tool === undefined) throw internal(`resolution lost node ${root.target}`);

  const txn = await Transaction.begin(store, "dlx");
  try {
    await txn.setState("fetching");
    const fetched = await fetchSources({
      store,
      registry,
      txn,
      requests: resolved.nodes.map((node) => ({
        key: node.key,
        name: node.name,
        version: node.version,
      })),
      ...(options.logger === undefined ? {} : { logger: options.logger }),
    });
    for (const node of resolved.nodes) {
      const committed = fetched.get(node.key);
      if (committed === undefined) throw internal(`fetch lost ${node.key}`);
      if (committed.sourceId !== node.sourceId) {
        throw new SnpmError(
          "SNPM_INTERNAL",
          `fetch skew for ${node.name}@${node.version}: resolved and committed identities disagree`,
          {
            detail: { name: node.name, version: node.version },
            remedy:
              "retry the operation; registries must serve immutable versioned content",
          },
        );
      }
    }
    await txn.setState("sources-committed");

    const graph = createGraphDoc(
      resolved.nodes.map((node) => ({
        key: node.key,
        name: node.name,
        version: node.version,
        sourceId: node.sourceId,
        deps: node.edges.map((edge) => ({
          name: edge.name,
          target: edge.target,
        })),
      })),
    );
    const realized = await realizeGraph({
      store,
      graph,
      ...(options.logger === undefined ? {} : { logger: options.logger }),
    });
    await txn.setState("realizations-ready");

    const toolRealization = realized.realizationDirByKey.get(tool.key);
    if (toolRealization === undefined)
      throw internal(`missing realization for ${tool.key}`);
    const toolPkgDir = packageDirIn(toolRealization, tool.name);

    await assertNoInstallScripts(realized.packageDirByKey, byKey);
    const binKey = selectBin(tool, options.binName);
    const binTarget = tool.bin[binKey];
    if (binTarget === undefined)
      throw internal(`selected bin ${binKey} vanished`);
    const script = await resolveBinScript(toolPkgDir, tool, binKey, binTarget);

    const envDir = await mkdtemp(path.join(os.tmpdir(), "snpm-dlx-"));
    try {
      await installProjection(envDir, [
        { name: tool.name, linkTarget: toolPkgDir },
      ]);
      return {
        ...(await runTool(script, args, cwd, env, options.capture === true)),
        key: tool.key,
        name: tool.name,
        version: tool.version,
        reused: realized.created.length === 0,
        envDir,
      };
    } finally {
      await rmrfNoFollow(envDir).catch((error: unknown) => {
        options.logger?.warn(
          `temporary tool environment at ${envDir} was not removed: ${String(error)}`,
        );
      });
    }
  } finally {
    await txn.finish().catch(() => {});
  }
}

// ---------------------------------------------------------------------------

/** Deny-by-default script policy: any install-time script blocks the run. */
async function assertNoInstallScripts(
  packageDirByKey: Map<string, string>,
  byKey: Map<string, ResolvedOccurrence>,
): Promise<void> {
  for (const [key, pkgDir] of packageDirByKey) {
    const node = byKey.get(key);
    const label = node === undefined ? key : `${node.name}@${node.version}`;
    let raw: unknown;
    try {
      raw = JSON.parse(
        await readFile(path.join(pkgDir, "package.json"), "utf8"),
      );
    } catch (error) {
      throw new SnpmError(
        "SNPM_RESOLUTION_FAILED",
        `tool closure package ${label} has no readable package.json`,
        {
          detail: { package: label },
          remedy: "tools must ship a readable package manifest",
          cause: error,
        },
      );
    }
    const scripts = (raw as { scripts?: unknown }).scripts;
    const table: Record<string, unknown> =
      typeof scripts === "object" && scripts !== null && !Array.isArray(scripts)
        ? (scripts as Record<string, unknown>)
        : {};
    for (const stage of ["preinstall", "install", "postinstall"]) {
      const script = table[stage];
      if (typeof script === "string" && script.trim() !== "") {
        throw new SnpmError(
          "SNPM_SCRIPT_BLOCKED",
          `tool ${label} declares install-time script "${stage}"`,
          {
            detail: { package: label, script: stage },
            remedy:
              "dependency lifecycle scripts are denied by default; remove the scripted dependency or approve it explicitly once script review is available",
          },
        );
      }
    }
  }
}

function selectBin(
  tool: ResolvedOccurrence,
  binName: string | undefined,
): string {
  const label = `${tool.name}@${tool.version}`;
  if (binName !== undefined) {
    if (tool.bin[binName] === undefined) {
      throw new SnpmError(
        "SNPM_RESOLUTION_FAILED",
        `tool ${label} has no bin entry "${binName}"`,
        {
          detail: {
            package: label,
            requested: binName,
            available: Object.keys(tool.bin),
          },
          remedy: "pick one of the available bin names",
        },
      );
    }
    return binName;
  }
  const names = Object.keys(tool.bin);
  if (names.length === 0) {
    throw new SnpmError(
      "SNPM_RESOLUTION_FAILED",
      `tool ${label} declares no executable bin entry`,
      {
        detail: { package: label },
        remedy:
          "tools run through their declared bin entry; pick a package that declares one",
      },
    );
  }
  const only = names[0];
  if (names.length === 1 && only !== undefined) return only;
  const short = tool.name.startsWith("@")
    ? (tool.name.split("/")[1] ?? tool.name)
    : tool.name;
  if (tool.bin[short] !== undefined) return short;
  throw new SnpmError(
    "SNPM_RESOLUTION_FAILED",
    `tool ${label} declares several bins (${names.join(", ")}); select one explicitly`,
    {
      detail: { package: label, available: names },
      remedy: "rerun with an explicit bin name",
    },
  );
}

async function resolveBinScript(
  pkgDir: string,
  tool: ResolvedOccurrence,
  binKey: string,
  target: string,
): Promise<string> {
  const label = `${tool.name}@${tool.version}`;
  const script = path.resolve(pkgDir, target);
  const relative = path.relative(pkgDir, script);
  if (
    relative === "" ||
    relative.startsWith("..") ||
    path.isAbsolute(relative)
  ) {
    throw new SnpmError(
      "SNPM_RESOLUTION_FAILED",
      `tool ${label} bin "${binKey}" escapes the package`,
      {
        detail: { package: label, bin: binKey },
        remedy: "bin targets must stay inside the package directory",
      },
    );
  }
  let stat;
  try {
    stat = await lstat(script);
  } catch (error) {
    throw new SnpmError(
      "SNPM_RESOLUTION_FAILED",
      `tool ${label} bin "${binKey}" is missing from the package`,
      {
        detail: { package: label, bin: binKey },
        remedy:
          "the registry archive does not match its manifest; report the package",
        cause: error,
      },
    );
  }
  if (!stat.isFile() && !stat.isSymbolicLink()) {
    throw new SnpmError(
      "SNPM_RESOLUTION_FAILED",
      `tool ${label} bin "${binKey}" is not a file`,
      {
        detail: { package: label, bin: binKey },
        remedy: "bin entries must point at executable files",
      },
    );
  }
  return script;
}

async function runTool(
  script: string,
  args: readonly string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
  capture: boolean,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script, ...args], {
      cwd,
      env,
      stdio: capture ? "pipe" : "inherit",
    });
    let stdout = "";
    let stderr = "";
    if (capture) {
      child.stdout?.on("data", (chunk: Buffer) => {
        stdout += chunk.toString();
      });
      child.stderr?.on("data", (chunk: Buffer) => {
        stderr += chunk.toString();
      });
    }
    child.on("error", (error) => {
      reject(
        new SnpmError("SNPM_INTERNAL", "failed to launch the tool process", {
          cause: error,
          remedy: "verify the Node.js executable is usable",
        }),
      );
    });
    child.on("close", (code, signal) => {
      resolve({ exitCode: closeCode(code, signal), stdout, stderr });
    });
  });
}

function internal(message: string): SnpmError {
  return new SnpmError("SNPM_INTERNAL", message);
}
