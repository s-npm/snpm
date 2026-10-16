/**
 * Registry-backed dependency resolver (SPEC 9).
 *
 * Turns requirement strings into an immutable resolved graph: exact name,
 * version, origin-qualified source identity, dependency edges, and peer
 * bindings. No package code runs here; no project files are touched.
 *
 * Scope of this slice: registry versions, ranges, tags, scoped names, and
 * npm aliases; prod and optional groups; required and optional peers with
 * explicit-consumer-context bindings; cycles; bundled subtrees (skipped,
 * never exposed). Dev groups need full packuments and arrive later, as do
 * overrides, platform filtering, and workspace relationships. Remote
 * tarballs, Git, and local sources fail explicitly (SPEC 9.2).
 *
 * Peer contexts (SPEC 9.3-9.4): one verified source may back several
 * dependency contexts. Occurrences that declare peers are instantiated per
 * requesting parent and keyed by a fingerprint of their resolved peer
 * closure, so identical bindings share one occurrence while differing
 * bindings stay distinct. Peerless occurrences share by name@version.
 */

import { maxSatisfying, satisfies, valid } from "semver";
import { SnpmError } from "../errors.ts";
import {
  expectedIntegrityFromDist,
  type Packument,
  type PackumentVersion,
} from "../fetch/registry.ts";
import { sha512Hex, sourceIdOf } from "../util/hash.ts";
import { canonicalJson } from "../util/json.ts";
import { parseRequirement } from "./spec.ts";

export type MetadataProvider = {
  readonly origin: string;
  packument(name: string): Promise<Packument>;
};

export type EdgeKind = "prod" | "optional" | "peer";

export type ResolvedEdge = {
  /** Dependency name as it appears in `node_modules` (alias-aware). */
  name: string;
  /** Final occurrence key of the resolved target. */
  target: string;
  kind: EdgeKind;
  /** Requested spec, kept for diagnostics. */
  spec: string;
};

export type ResolvedOccurrence = {
  key: string;
  /** Registry package name; aliases live on edges, never here. */
  name: string;
  version: string;
  sourceId: string;
  integrity: string;
  /** Credential-free registry origin (SPEC 8.1). */
  origin: string;
  tarballUrl: string;
  bin: Record<string, string>;
  edges: ResolvedEdge[];
  peerBindings: Array<{ name: string; target: string | null }>;
  platform: { os?: string[]; cpu?: string[]; libc?: string[] };
  engines?: Record<string, string>;
};

export type ResolveOptions = {
  provider: MetadataProvider;
  requirements: Array<{ name: string; spec: string }>;
};

export type FinalizedGraph = {
  nodes: ResolvedOccurrence[];
  /** Root requirement edge name -> occurrence key. */
  roots: Array<{ name: string; target: string }>;
};

export async function resolveRequirements(
  options: ResolveOptions,
): Promise<FinalizedGraph> {
  const state = new ResolverState(options.provider);
  const rootFrame: Frame = { label: "<root>", children: [] };
  const seenRoots = new Set<string>();
  for (const requirement of [...options.requirements].sort((a, b) =>
    compareStrings(a.name, b.name),
  )) {
    if (seenRoots.has(requirement.name)) continue;
    seenRoots.add(requirement.name);
    const child = await state.buildChild(
      rootFrame,
      [],
      requirement.name,
      requirement.spec,
      "prod",
    );
    rootFrame.children.push({
      edgeName: requirement.name,
      kind: "prod",
      spec: requirement.spec,
      child,
    });
  }
  await state.bindPeersToFixpoint();
  return state.finalize(
    rootFrame.children.map((link) => ({
      name: link.edgeName,
      child: link.child,
    })),
  );
}

// ---------------------------------------------------------------------------
// Internal occurrence graph. Edges reference occurrences, never key strings,
// until finalization assigns deterministic keys.
// ---------------------------------------------------------------------------

type ChildLink = {
  edgeName: string;
  kind: "prod" | "optional" | "peer";
  spec: string;
  child: Occurrence;
};

type Frame = {
  label: string;
  children: ChildLink[];
};

type PeerSpec = {
  name: string;
  range: string;
  optional: boolean;
};

type Occurrence = {
  name: string;
  version: string;
  entry: PackumentVersion;
  integrity: string;
  children: ChildLink[];
  peerSpecs: PeerSpec[];
  /** peer name -> bound occurrence, null for absent optional peers. */
  peerBindings: Map<string, Occurrence | null>;
  /** Creation stack, root-first; only populated when peers are declared. */
  chain: Frame[];
};

class ResolverState {
  readonly provider: MetadataProvider;
  private readonly packuments = new Map<string, Promise<Packument>>();
  private readonly peerless = new Map<string, Occurrence>();
  private readonly peerBearing = new Map<Frame, Map<string, Occurrence>>();
  private readonly freshPeers = new Map<Occurrence, Map<string, Occurrence>>();
  private readonly occurrences: Occurrence[] = [];

  constructor(provider: MetadataProvider) {
    this.provider = provider;
  }

  /** Cached packument fetch shared by version selection. */
  packumentOf(name: string): Promise<Packument> {
    const cached = this.packuments.get(name);
    if (cached !== undefined) return cached;
    const pending = this.provider.packument(name);
    this.packuments.set(name, pending);
    return pending;
  }

  /**
   * Build (or reuse) the occurrence for one dependency edge. Peerless
   * packages share one occurrence per name@version; packages declaring
   * peers are instantiated per requesting parent frame so each gets the
   * bindings of its own consumer context.
   */
  async buildChild(
    parentFrame: Frame,
    chain: Frame[],
    edgeName: string,
    rawSpec: string,
    kind: "prod" | "optional",
  ): Promise<Occurrence> {
    const req = parseRequirement(edgeName, rawSpec);
    const { version, entry } = await selectVersion(this, req);
    const integrity = expectedIntegrityFromDist(entry.dist);
    if (integrity === undefined) {
      throw new SnpmError(
        "SNPM_INTEGRITY_FAILED",
        `registry metadata for ${req.realName}@${version} carries no integrity digest`,
        {
          detail: { name: req.realName, version },
          remedy:
            "strict policy rejects unpinned archives; configure the origin-verification policy explicitly to accept and pin one",
        },
      );
    }
    const baseKey = `${req.realName}@${version}`;
    const hasPeers = peerSpecsOf(entry).length > 0;

    if (!hasPeers) {
      const existing = this.peerless.get(baseKey);
      if (existing !== undefined) return existing;
    } else {
      let perParent = this.peerBearing.get(parentFrame);
      if (perParent === undefined) {
        perParent = new Map();
        this.peerBearing.set(parentFrame, perParent);
      } else {
        const existing = perParent.get(baseKey);
        if (existing !== undefined) return existing;
      }
    }

    const occ: Occurrence = {
      name: req.realName,
      version,
      entry,
      integrity,
      children: [],
      peerSpecs: peerSpecsOf(entry),
      peerBindings: new Map(),
      chain: hasPeers ? [...chain, parentFrame] : [],
    };
    if (!hasPeers) this.peerless.set(baseKey, occ);
    else this.peerBearing.get(parentFrame)?.set(baseKey, occ);
    this.occurrences.push(occ);

    const selfFrame: Frame = { label: baseKey, children: occ.children };
    const childChain = [...chain, parentFrame];
    for (const dep of regularDepsOf(entry)) {
      const child = await this.buildChild(
        selfFrame,
        childChain,
        dep.name,
        dep.spec,
        dep.kind,
      );
      occ.children.push({
        edgeName: dep.name,
        kind: dep.kind,
        spec: dep.spec,
        child,
      });
    }
    return occ;
  }

  /**
   * Bind every declared peer against the built tree, iterating until a full
   * round changes nothing. Re-evaluation converges: the tree only grows
   * (fresh auto-selected peers, memoized per requester), and a binding only
   * ever moves to a nearer candidate, so movement is bounded by tree depth.
   */
  async bindPeersToFixpoint(): Promise<void> {
    for (;;) {
      let changed = false;
      for (const occ of this.occurrences) {
        for (const spec of occ.peerSpecs) {
          if (await this.bindOne(occ, spec)) changed = true;
        }
      }
      if (!changed) return;
    }
  }

  /**
   * One binding attempt. Returns true when the binding moved, a fresh node
   * was created, or an absent optional was recorded.
   */
  private async bindOne(occ: Occurrence, spec: PeerSpec): Promise<boolean> {
    const current = occ.peerBindings.get(spec.name);
    const lookup = lookupPeer(occ, spec.name, spec.range);
    if (lookup.status === "conflict") {
      throw peerConflict(occ, spec, lookup.found);
    }
    if (lookup.status === "absent") {
      if (spec.optional) {
        if (current === undefined) {
          occ.peerBindings.set(spec.name, null);
          return true;
        }
        if (current !== null)
          throw internal(`optional peer ${spec.name} lost its binding`);
        return false;
      }
      const fresh = await this.freshPeer(occ, spec);
      return this.attachPeer(occ, spec, fresh);
    }
    return this.attachPeer(occ, spec, lookup.target);
  }

  /** Point a peer edge at its target, replacing any superseded peer link. */
  private attachPeer(
    occ: Occurrence,
    spec: PeerSpec,
    target: Occurrence,
  ): boolean {
    const linked = occ.children.some(
      (link) => link.edgeName === spec.name && link.child === target,
    );
    if (occ.peerBindings.get(spec.name) === target && linked) return false;
    occ.peerBindings.set(spec.name, target);
    occ.children = occ.children.filter(
      (link) => !(link.kind === "peer" && link.edgeName === spec.name),
    );
    occ.children.push({
      edgeName: spec.name,
      kind: "peer",
      spec: spec.range,
      child: target,
    });
    return true;
  }

  /**
   * Auto-select a missing required peer (SPEC 9.3): resolve it fresh under
   * the requesting occurrence. Memoized per requester so the tree stays
   * finite; the fresh subtree binds against the growing tree in later
   * rounds.
   */
  private async freshPeer(
    occ: Occurrence,
    spec: PeerSpec,
  ): Promise<Occurrence> {
    let perOcc = this.freshPeers.get(occ);
    if (perOcc === undefined) {
      perOcc = new Map();
      this.freshPeers.set(occ, perOcc);
    }
    const existing = perOcc.get(spec.name);
    if (existing !== undefined) return existing;
    const req = parseRequirement(spec.name, spec.range);
    const { version, entry } = await selectVersion(this, {
      realName: req.realName,
      targetSpec: req.targetSpec,
      targetKind: req.targetKind,
    });
    const integrity = expectedIntegrityFromDist(entry.dist);
    if (integrity === undefined) {
      throw new SnpmError(
        "SNPM_INTEGRITY_FAILED",
        `registry metadata for ${req.realName}@${version} carries no integrity digest`,
        {
          detail: { name: req.realName, version },
          remedy:
            "strict policy rejects unpinned archives; configure the origin-verification policy explicitly to accept and pin one",
        },
      );
    }
    const fresh: Occurrence = {
      name: req.realName,
      version,
      entry,
      integrity,
      children: [],
      peerSpecs: peerSpecsOf(entry),
      peerBindings: new Map(),
      chain: [...occ.chain, this.frameOf(occ)],
    };
    perOcc.set(spec.name, fresh);
    this.occurrences.push(fresh);
    const selfFrame = this.frameOf(fresh);
    for (const dep of regularDepsOf(entry)) {
      const child = await this.buildChild(
        selfFrame,
        fresh.chain,
        dep.name,
        dep.spec,
        dep.kind,
      );
      fresh.children.push({
        edgeName: dep.name,
        kind: dep.kind,
        spec: dep.spec,
        child,
      });
    }
    return fresh;
  }

  private readonly frames = new Map<Occurrence, Frame>();

  /** Stable lookup frame for an occurrence (live children view). */
  private frameOf(occ: Occurrence): Frame {
    let frame = this.frames.get(occ);
    if (frame === undefined) {
      frame = { label: `${occ.name}@${occ.version}`, children: occ.children };
      this.frames.set(occ, frame);
    }
    return frame;
  }

  /**
   * Final deterministic keys, merge checks, reachability pruning, and output
   * records. Unreachable occurrences (superseded peer links leave their old
   * targets behind) are dropped so the document is exactly the reachable
   * closure of the requirements.
   */
  finalize(
    rootLinks: Array<{ name: string; child: Occurrence }>,
  ): FinalizedGraph {
    const keys = new Map<Occurrence, string>();
    for (const occ of this.occurrences) {
      keys.set(occ, occurrenceKey(occ));
    }
    const reachable = new Set<Occurrence>();
    const visit = (occ: Occurrence): void => {
      if (reachable.has(occ)) return;
      reachable.add(occ);
      for (const link of occ.children) {
        const child = link.child;
        if (child !== undefined) visit(child);
      }
    };
    for (const link of rootLinks) visit(link.child);
    const byKey = new Map<string, Occurrence>();
    for (const occ of reachable) {
      const key = keys.get(occ);
      if (key === undefined) throw internal("missing finalized key");
      const existing = byKey.get(key);
      if (existing !== undefined) {
        assertMergeable(existing, occ, keys, this.provider.origin);
        continue;
      }
      byKey.set(key, occ);
    }
    const nodes = [...byKey.entries()]
      .sort((a, b) => compareStrings(a[0], b[0]))
      .map(([key, occ]) => toResolved(occ, key, keys, this.provider.origin));
    const roots = rootLinks.map((link) => {
      const target = keys.get(link.child);
      if (target === undefined)
        throw internal(`missing key for root ${link.name}`);
      return { name: link.name, target };
    });
    return { nodes, roots };
  }
}

// ---------------------------------------------------------------------------
// Version selection
// ---------------------------------------------------------------------------

async function selectVersion(
  state: ResolverState,
  req: {
    realName: string;
    targetSpec: string;
    targetKind: "exact" | "range" | "tag";
  },
): Promise<{ version: string; entry: PackumentVersion }> {
  const packument = await state.packumentOf(req.realName);
  const fail = (message: string, remedy: string): SnpmError =>
    new SnpmError("SNPM_RESOLUTION_FAILED", message, {
      detail: { name: req.realName, spec: req.targetSpec },
      remedy,
    });
  switch (req.targetKind) {
    case "exact": {
      const entry = packument.versions[req.targetSpec];
      if (entry === undefined) {
        throw fail(
          `registry has no version ${req.targetSpec} of ${req.realName}`,
          "check the requested version exists in the configured registry",
        );
      }
      return { version: req.targetSpec, entry };
    }
    case "tag": {
      const target = packument.distTags[req.targetSpec];
      if (target === undefined) {
        throw fail(
          `registry has no dist-tag ${req.targetSpec} for ${req.realName}`,
          "check the tag name or use an exact version",
        );
      }
      const entry = packument.versions[target];
      if (entry === undefined) {
        throw fail(
          `dist-tag ${req.targetSpec} of ${req.realName} points at missing version ${target}`,
          "report the registry response; tags must resolve to published versions",
        );
      }
      return { version: target, entry };
    }
    case "range": {
      const candidates = Object.keys(packument.versions).filter(
        (v) => valid(v) !== null,
      );
      const version = maxSatisfying(candidates, req.targetSpec);
      if (version === null) {
        throw fail(
          `no version of ${req.realName} satisfies ${req.targetSpec}`,
          "relax the range or check which versions the registry publishes",
        );
      }
      const entry = packument.versions[version];
      if (entry === undefined)
        throw internal(`selected version ${version} vanished`);
      return { version, entry };
    }
  }
}

// ---------------------------------------------------------------------------
// Peer lookup and fingerprints
// ---------------------------------------------------------------------------

type LookupResult =
  | { status: "bound"; target: Occurrence }
  | { status: "absent" }
  | { status: "conflict"; found: Array<{ version: string; via: string }> };

/**
 * Nearest-first peer lookup from the requesting occurrence outward: its own
 * children, then each chain frame's children innermost-first. A same-named
 * but incompatible candidate is a conflict, never a reason to look further
 * out (SPEC 9.3 fails incompatible required sets by default).
 */
function lookupPeer(
  occ: Occurrence,
  peerName: string,
  range: string,
): LookupResult {
  const levels: Array<{ label: string; children: ChildLink[] }> = [
    { label: `${occ.name}@${occ.version}`, children: occ.children },
    ...[...occ.chain].reverse(),
  ];
  for (const level of levels) {
    const matches = level.children.filter((link) => link.edgeName === peerName);
    if (matches.length === 0) continue;
    const satisfying = matches.filter((link) =>
      satisfies(link.child.version, range),
    );
    const first = satisfying[0];
    if (first !== undefined) return { status: "bound", target: first.child };
    return {
      status: "conflict",
      found: matches.map((link) => ({
        version: link.child.version,
        via: level.label,
      })),
    };
  }
  return { status: "absent" };
}

function peerConflict(
  occ: Occurrence,
  spec: PeerSpec,
  found: Array<{ version: string; via: string }>,
): SnpmError {
  const chain = [
    ...occ.chain.map((frame) => frame.label),
    `${occ.name}@${occ.version}`,
  ];
  return new SnpmError(
    "SNPM_PEER_CONFLICT",
    `incompatible peer ${spec.name}@${spec.range} required by ${occ.name}@${occ.version}`,
    {
      detail: {
        chain,
        peer: spec.name,
        range: spec.range,
        found: found.map((entry) => `${entry.version} via ${entry.via}`),
      },
      remedy: "align the versions or declare an intentional override",
    },
  );
}

/** Canonical fingerprint over the transitive peer closure (SPEC 9.4). */
function occurrenceKey(occ: Occurrence): string {
  const base = `${occ.name}@${occ.version}`;
  if (occ.peerSpecs.length === 0) return base;
  const expansion = expandPeerBindings(occ, new Set<Occurrence>([occ]));
  return `${base}#${sha512Hex(canonicalJson(expansion)).slice(0, 12)}`;
}

function expandPeerBindings(
  occ: Occurrence,
  visiting: Set<Occurrence>,
): unknown {
  const parts: Array<[string, unknown]> = [];
  for (const spec of occ.peerSpecs) {
    const bound = occ.peerBindings.get(spec.name);
    if (bound === undefined)
      throw internal(`unbound peer ${spec.name} at finalization`);
    if (bound === null) {
      parts.push([spec.name, "absent"]);
    } else if (visiting.has(bound)) {
      parts.push([spec.name, ["ref", `${bound.name}@${bound.version}`]]);
    } else {
      parts.push([
        spec.name,
        [
          "node",
          `${bound.name}@${bound.version}`,
          expandPeerBindings(bound, new Set([...visiting, occ])),
        ],
      ]);
    }
  }
  return parts;
}

function assertMergeable(
  a: Occurrence,
  b: Occurrence,
  keys: Map<Occurrence, string>,
  origin: string,
): void {
  const sourceA = sourceIdForOccurrence(a, origin);
  const sourceB = sourceIdForOccurrence(b, origin);
  if (sourceA !== sourceB) {
    throw new SnpmError(
      "SNPM_RESOLUTION_FAILED",
      `same occurrence key selects different sources for ${a.name}@${a.version}`,
      {
        detail: { key: keys.get(a), sources: [sourceA, sourceB] },
        remedy:
          "a public and a private registry publishing the same name/version are not the same trusted identity",
      },
    );
  }
  const edgesA = canonicalJson(
    a.children.map((link) => [link.edgeName, keys.get(link.child)]),
  );
  const edgesB = canonicalJson(
    b.children.map((link) => [link.edgeName, keys.get(link.child)]),
  );
  if (edgesA !== edgesB) {
    throw internal(
      `same occurrence key with different edges for ${a.name}@${a.version}`,
    );
  }
}

function toResolved(
  occ: Occurrence,
  key: string,
  keys: Map<Occurrence, string>,
  origin: string,
): ResolvedOccurrence {
  const edges: ResolvedEdge[] = occ.children.map((link) => {
    const target = keys.get(link.child);
    if (target === undefined) throw internal(`missing key for child of ${key}`);
    return { name: link.edgeName, target, kind: link.kind, spec: link.spec };
  });
  const peerBindings = occ.peerSpecs.map((spec) => {
    const bound = occ.peerBindings.get(spec.name);
    if (bound === undefined)
      throw internal(`unbound peer ${spec.name} of ${key}`);
    if (bound === null) return { name: spec.name, target: null };
    const target = keys.get(bound);
    if (target === undefined) throw internal(`missing key for peer of ${key}`);
    return { name: spec.name, target };
  });
  return {
    key,
    name: occ.name,
    version: occ.version,
    sourceId: sourceIdForOccurrence(occ, origin),
    integrity: occ.integrity,
    origin,
    tarballUrl: occ.entry.dist.tarball,
    bin: normalizeBin(occ.name, occ.entry.bin),
    edges,
    peerBindings,
    platform: {
      ...(occ.entry.os === undefined ? {} : { os: occ.entry.os }),
      ...(occ.entry.cpu === undefined ? {} : { cpu: occ.entry.cpu }),
      ...(occ.entry.libc === undefined ? {} : { libc: occ.entry.libc }),
    },
    ...(occ.entry.engines === undefined ? {} : { engines: occ.entry.engines }),
  };
}

function sourceIdForOccurrence(occ: Occurrence, origin: string): string {
  return sourceIdOf({
    sourceType: "registry",
    name: occ.name,
    version: occ.version,
    origin,
    integrity: occ.integrity,
  });
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function peerSpecsOf(entry: PackumentVersion): PeerSpec[] {
  return Object.keys(entry.peerDependencies ?? {})
    .sort(compareStrings)
    .map((peerName) => ({
      name: peerName,
      range: entry.peerDependencies?.[peerName] ?? "*",
      optional: entry.peerDependenciesMeta?.[peerName]?.optional === true,
    }));
}

function regularDepsOf(
  entry: PackumentVersion,
): Array<{ name: string; spec: string; kind: "prod" | "optional" }> {
  const bundled = new Set<string>();
  if (Array.isArray(entry.bundledDependencies)) {
    for (const name of entry.bundledDependencies) bundled.add(name);
  }
  const bundleAll = entry.bundledDependencies === true;
  const seen = new Set<string>();
  const deps: Array<{ name: string; spec: string; kind: "prod" | "optional" }> =
    [];
  const push = (
    name: string,
    spec: string,
    kind: "prod" | "optional",
  ): void => {
    if (seen.has(name) || bundled.has(name) || bundleAll) return;
    seen.add(name);
    deps.push({ name, spec, kind });
  };
  for (const name of Object.keys(entry.dependencies ?? {}).sort(
    compareStrings,
  )) {
    push(name, entry.dependencies?.[name] ?? "", "prod");
  }
  for (const name of Object.keys(entry.optionalDependencies ?? {}).sort(
    compareStrings,
  )) {
    push(name, entry.optionalDependencies?.[name] ?? "", "optional");
  }
  return deps;
}

function normalizeBin(
  name: string,
  bin: PackumentVersion["bin"],
): Record<string, string> {
  if (typeof bin === "string") {
    const short = name.startsWith("@") ? (name.split("/")[1] ?? name) : name;
    return { [short]: bin };
  }
  if (typeof bin !== "object" || bin === null) return {};
  const out: Record<string, string> = {};
  for (const [binName, target] of Object.entries(bin)) {
    if (typeof target === "string") out[binName] = target;
  }
  return out;
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function internal(message: string): SnpmError {
  return new SnpmError("SNPM_INTERNAL", message);
}
