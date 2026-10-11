// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

// Hashline file-header sigils (`[path#XXXX]`), pinned from
// @oh-my-pi/hashline src/format.ts — frozen protocol constants. Deep
// omp-family subpath imports do not resolve under omp's legacy extension
// bundle, so they are inlined rather than imported.
const HL_FILE_PREFIX = '[';
const HL_FILE_SUFFIX = ']';
const HL_FILE_HASH_SEP = '#';
const HL_FILE_HASH_LENGTH = 4;

// omp internal-urls/xd-protocol parseXdUrl, pinned: omp's extension host
// bundles a legacy module map where deep pi-coding-agent subpaths do not
// resolve, so the semantics live here.
function parseXdUrl(input: string): { name: string | null } | null {
  const trimmed = input.trim();
  if (!trimmed.toLowerCase().startsWith('xd://')) return null;
  const name = trimmed.slice(5);
  if (name.length === 0) return { name: null };
  if (/[/?#]/.test(name)) return null;
  return { name };
}

export type WriteTargetKind = 'fs' | 'ssh' | 'xd' | 'internal' | 'unknown';

export interface WriteTarget {
  tool: string;
  /** Field value exactly as the caller provided it. */
  raw: string;
  /** Unwrapped/peeled path the policy gates on; '' for unknown targets. */
  path: string;
  kind: WriteTargetKind;
  /** Internal-URL scheme (local, vault, conflict, ...). */
  scheme?: string;
  /** xd:// device name, '' when the target is a bare `xd://` listing. */
  device?: string;
}

export const GATED_WRITE_TOOLS: Record<string, true> = { write: true, edit: true, ast_edit: true };

// Keep the replicated rules below in sync with omp; each cites its source.
// Under-peeling only causes an extra approval prompt (fail-closed), never a
// bypass — the write tool re-derives the real target with full fidelity.

// omp tools/path-utils.ts TOP_LEVEL_INTERNAL_URL_PREFIXES — case-sensitive
// startsWith there; a cased variant here just fails closed to a prompt.
const INTERNAL_URL_PREFIXES = [
  'agent://',
  'artifact://',
  'skill://',
  'rule://',
  'security://',
  'local://',
  'mcp://',
  'ssh://',
  'vault://',
] as const;

const INTERNAL_SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\//i;
const HASHLINE_TAG_RE = new RegExp(`${HL_FILE_HASH_SEP}[0-9A-Fa-f]{${HL_FILE_HASH_LENGTH}}$`);

/** omp tools/plan-mode-guard.ts unwrapHashlineHeaderPath: strip a strict
 *  `[path]` / `[path#XXXX]` wrapper; anything else returns the input. */
function unwrapHashlineWrapper(targetPath: string): string {
  const trimmed = targetPath.trimEnd();
  if (
    trimmed.length < HL_FILE_PREFIX.length + HL_FILE_SUFFIX.length ||
    trimmed[0] !== HL_FILE_PREFIX ||
    trimmed[trimmed.length - 1] !== HL_FILE_SUFFIX
  ) {
    return targetPath;
  }
  const inner = trimmed.slice(HL_FILE_PREFIX.length, trimmed.length - HL_FILE_SUFFIX.length);
  const tagMatch = HASHLINE_TAG_RE.exec(inner);
  const pathPart = tagMatch ? inner.slice(0, tagMatch.index) : inner;
  if (pathPart.length === 0 || pathPart.includes(HL_FILE_HASH_SEP)) {
    return targetPath;
  }
  return pathPart;
}

/** omp write.ts peels whole-file selectors (`:raw`, `:conflicts`) from
 *  internal-URL targets only; line-range selectors make write itself throw a
 *  precise error, so they stay verbatim here. */
function prepareWritePath(raw: string): string {
  const unwrapped = unwrapHashlineWrapper(raw);
  const selector = /:(raw|conflicts)$/i.exec(unwrapped);
  if (selector && INTERNAL_SCHEME_RE.test(unwrapped)) {
    return unwrapped.slice(0, selector.index);
  }
  return unwrapped;
}

function classifyWriteTarget(tool: string, raw: string, path: string): WriteTarget {
  // Substring on purpose (parity with omp pathTargetsSsh): catches smuggled
  // ssh:// entries inside delimited path lists before expansion.
  if (/ssh:\/\//i.test(path)) {
    return { tool, raw, path, kind: 'ssh' };
  }
  const xd = parseXdUrl(path);
  if (xd) {
    return { tool, raw, path, kind: 'xd', device: xd.name ?? '' };
  }
  // conflict:// is not an InternalUrlRouter prefix; write routes it to
  // in-memory merge-resolution state. Malformed ids never touch the
  // filesystem either, so an anchored check is safe for gating.
  if (/^conflict:\/\//i.test(path)) {
    return { tool, raw, path, kind: 'internal', scheme: 'conflict' };
  }
  // omp normalizeLocalScheme: local:/x → local://x
  const normalized = path.replace(/^(local:)\/(?!\/)/i, '$1//');
  const prefix = INTERNAL_URL_PREFIXES.find((candidate) => normalized.startsWith(candidate));
  if (prefix) {
    return { tool, raw, path, kind: 'internal', scheme: prefix.slice(0, -3) };
  }
  return { tool, raw, path, kind: 'fs' };
}

function stringEntries(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === 'string' && entry.length > 0);
}

export function extractWriteTargets(toolName: string, input: unknown): WriteTarget[] {
  if (!GATED_WRITE_TOOLS[toolName] || typeof input !== 'object' || input === null) {
    return [];
  }
  const args = input as Record<string, unknown>;
  const directPath = typeof args.path === 'string' && args.path.length > 0 ? args.path : undefined;
  const rawPaths =
    toolName === 'write'
      ? directPath
        ? [directPath]
        : []
      : [...stringEntries(args.paths), ...(directPath ? [directPath] : [])];

  if (rawPaths.length === 0) {
    // No extractable target on a gated tool: fail closed rather than pass through.
    return [{ tool: toolName, raw: '', path: '', kind: 'unknown' }];
  }

  const targets: WriteTarget[] = [];
  const seen = new Set<string>();
  for (const raw of rawPaths) {
    const path = toolName === 'write' ? prepareWritePath(raw) : raw;
    const target = classifyWriteTarget(toolName, raw, path);
    const key = `${target.kind}\u0000${target.path}`;
    if (seen.has(key)) continue;
    seen.add(key);
    targets.push(target);
  }
  return targets;
}
