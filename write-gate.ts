// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { canonicalizePath, matchesPathPattern } from '@landstrip/landstrip-api/shared';

import type { WriteTarget } from './write-targets.ts';

// omp resolution devices (tools/resolve.ts) and the QA report device
// (tools/report-tool-issue.ts) are read-tier, preview-backed dispatches.
export const DEFAULT_XD_WRITE_DEVICES: readonly string[] = [
  'resolve',
  'reject',
  'propose',
  'report_issue',
];

export interface WritePolicyConfig {
  cwd: string;
  denyWrite: string[];
  denyWriteAlways: string[];
  /** Effective allowlist: config + session + execution allowances. */
  allowWrite: string[];
  xdDevices?: readonly string[];
}

export type WriteGateDecision =
  | { action: 'allow' }
  | { action: 'deny'; reason: string }
  | { action: 'prompt'; displayPath: string; title: string };

function deniedBy(path: string, patterns: string[], cwd: string): boolean {
  return matchesPathPattern(path, patterns, cwd);
}

/**
 * Pure per-target decision. The write tool re-derives its real target with
 * full fidelity at execution time; this judgment only decides whether the
 * tool_call may proceed, so approximation errs toward prompting.
 */
export function judgeWriteTarget(
  target: WriteTarget,
  config: WritePolicyConfig,
): WriteGateDecision {
  if (target.kind === 'unknown') {
    return {
      action: 'deny',
      reason: `Sandbox: could not determine the write target of a ${target.tool} call — refusing.`,
    };
  }
  if (target.kind === 'internal') {
    // local:// (plan sandbox) and conflict:// (merge-resolution state) are
    // session-owned memory, not host filesystem.
    if (target.scheme === 'local' || target.scheme === 'conflict') {
      return { action: 'allow' };
    }
    return {
      action: 'prompt',
      displayPath: target.raw,
      title: `Write blocked: "${target.raw}" uses internal URL scheme "${target.scheme}" outside sandbox policy`,
    };
  }
  if (target.kind === 'ssh') {
    if (deniedBy(target.path, [...config.denyWriteAlways, ...config.denyWrite], config.cwd)) {
      return {
        action: 'deny',
        reason: `Sandbox: write access denied for "${target.path}" (denyWrite). Remote ssh:// writes bypass the sandbox.`,
      };
    }
    // Remote writes execute outside the sandbox; prompt every time regardless
    // of any allowWrite entry.
    return {
      action: 'prompt',
      displayPath: target.path,
      title: `Write blocked: remote write "${target.path}" (ssh://) bypasses the sandbox`,
    };
  }
  if (target.kind === 'xd') {
    const devices = config.xdDevices ?? DEFAULT_XD_WRITE_DEVICES;
    if (target.device && devices.includes(target.device)) {
      return { action: 'allow' };
    }
    return {
      action: 'prompt',
      displayPath: `xd://${target.device}`,
      title: `Write blocked: xd:// device "${target.device || '(none)'}" is not in the allowed device list`,
    };
  }

  // Filesystem target: sqlite rows and archive members address a container
  // file (`db.sqlite:table:key`, `a.zip:member`), so policy runs against the
  // container path while deny patterns also see the full string.
  const full = canonicalizePath(target.path, config.cwd);
  const colon = full.indexOf(':');
  const container = colon > 0 ? full.slice(0, colon) : full;
  const display = container !== full ? container : full;
  if (
    deniedBy(container, config.denyWriteAlways, config.cwd) ||
    deniedBy(full, config.denyWriteAlways, config.cwd)
  ) {
    return {
      action: 'deny',
      reason: `Sandbox: write access denied for "${display}" (denyWriteAlways).`,
    };
  }
  if (
    deniedBy(container, config.denyWrite, config.cwd) ||
    deniedBy(full, config.denyWrite, config.cwd)
  ) {
    return { action: 'deny', reason: `Sandbox: write access denied for "${display}" (denyWrite).` };
  }
  if (matchesPathPattern(container, config.allowWrite, config.cwd)) {
    return { action: 'allow' };
  }
  return {
    action: 'prompt',
    displayPath: container,
    title: `Write blocked: "${container}" is not in allowWrite`,
  };
}

export interface WriteGateDeps extends WritePolicyConfig {
  /**
   * Show the approval prompt and persist the caller's choice. Returning
   * 'allow' asserts the choice was applied; 'deny' (also on abort, missing
   * UI, or timeout) blocks the tool call.
   */
  prompt: (
    decision: { displayPath: string; title: string },
    target: WriteTarget,
  ) => Promise<'allow' | 'deny'>;
}

/**
 * Fold the per-target decisions into one tool_call verdict: the first denied
 * or prompt-denied target blocks the whole call.
 */
export async function gateWriteTargets(
  targets: WriteTarget[],
  deps: WriteGateDeps,
): Promise<{ block: true; reason: string } | undefined> {
  for (const target of targets) {
    const decision = judgeWriteTarget(target, deps);
    if (decision.action === 'deny') {
      return { block: true, reason: decision.reason };
    }
    if (decision.action === 'prompt') {
      const answer = await deps.prompt(decision, target);
      if (answer !== 'allow') {
        return { block: true, reason: decision.title };
      }
    }
  }
  return undefined;
}
