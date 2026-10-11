// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import type { WriteTarget } from './write-targets.ts';
import { DEFAULT_XD_WRITE_DEVICES, gateWriteTargets, judgeWriteTarget } from './write-gate.ts';

function target(
  tool: string,
  path: string,
  kind: WriteTarget['kind'] = 'fs',
  extra: Partial<WriteTarget> = {},
): WriteTarget {
  return { tool, raw: path, path, kind, ...extra };
}

function policy(overrides: Partial<Parameters<typeof judgeWriteTarget>[1]> = {}) {
  return {
    cwd: mkdtempSync(join(tmpdir(), 'omp-landstrip-gate-')),
    denyWrite: [],
    denyWriteAlways: [],
    allowWrite: [],
    ...overrides,
  };
}

function prompting(answers: Array<'allow' | 'deny'>) {
  const calls: Array<{ displayPath: string; title: string }> = [];
  let index = 0;
  return {
    calls,
    prompt: async (decision: { displayPath: string; title: string }) => {
      calls.push(decision);
      return answers[index++] ?? 'deny';
    },
  };
}

describe('judgeWriteTarget', () => {
  it('fails closed for unknown targets', () => {
    const decision = judgeWriteTarget(target('edit', '', 'unknown'), policy());
    expect(decision.action).toBe('deny');
  });

  it('allows session-owned local:// and conflict:// targets', () => {
    expect(
      judgeWriteTarget(target('write', 'local://a.md', 'internal', { scheme: 'local' }), policy())
        .action,
    ).toBe('allow');
    expect(
      judgeWriteTarget(
        target('write', 'conflict://7', 'internal', { scheme: 'conflict' }),
        policy(),
      ).action,
    ).toBe('allow');
  });

  it('prompts for other internal URL schemes such as vault://', () => {
    const decision = judgeWriteTarget(
      target('write', 'vault://n.md', 'internal', { scheme: 'vault' }),
      policy(),
    );
    expect(decision.action).toBe('prompt');
  });

  it('allows default xd:// devices without a prompt and prompts for others', () => {
    expect(DEFAULT_XD_WRITE_DEVICES).toContain('report_issue');
    expect(
      judgeWriteTarget(
        target('write', 'xd://report_issue', 'xd', { device: 'report_issue' }),
        policy(),
      ).action,
    ).toBe('allow');
    expect(
      judgeWriteTarget(target('write', 'xd://lsp', 'xd', { device: 'lsp' }), policy()).action,
    ).toBe('prompt');
    expect(
      judgeWriteTarget(
        target('write', 'xd://lsp', 'xd', { device: 'lsp' }),
        policy({ xdDevices: ['lsp'] }),
      ).action,
    ).toBe('allow');
  });

  it('blocks fs targets matching denyWrite or denyWriteAlways', () => {
    const deny = policy({ denyWrite: ['*.sqlite'] });
    expect(judgeWriteTarget(target('write', join(deny.cwd, 'db.sqlite')), deny).action).toBe(
      'deny',
    );
    const always = policy({ denyWriteAlways: ['secrets/**'] });
    expect(
      judgeWriteTarget(target('edit', join(always.cwd, 'secrets', 'k.txt')), always).action,
    ).toBe('deny');
  });

  it('applies fs policy to the sqlite/archive container path', () => {
    const cfg = policy({ denyWrite: ['**/*.sqlite'] });
    const decision = judgeWriteTarget(target('write', join('data', 'db.sqlite:rows:1')), cfg);
    expect(decision.action).toBe('deny');
  });

  it('allows fs targets covered by allowWrite and prompts otherwise', () => {
    expect(
      judgeWriteTarget(target('write', join('src', 'a.ts')), policy({ allowWrite: ['src/**'] }))
        .action,
    ).toBe('allow');
    expect(
      judgeWriteTarget(target('write', join('src', 'a.ts')), policy({ allowWrite: [] })).action,
    ).toBe('prompt');
  });

  it('checks ssh URIs against deny patterns and otherwise always prompts', () => {
    expect(
      judgeWriteTarget(target('write', 'ssh://h/x', 'ssh'), policy({ denyWrite: ['ssh://**'] }))
        .action,
    ).toBe('deny');
    const prompt = judgeWriteTarget(
      target('write', 'ssh://h/x', 'ssh'),
      policy({ allowWrite: ['ssh://h/**'] }),
    );
    expect(prompt.action).toBe('prompt');
  });
});

describe('gateWriteTargets', () => {
  it('blocks on the first denied target with its reason', async () => {
    const result = await gateWriteTargets(
      [target('write', join('src', 'ok.ts')), target('edit', join('etc', 'bad.ts'))],
      {
        ...policy({ allowWrite: ['src/**'], denyWrite: ['etc/**'] }),
        prompt: async () => 'allow',
      },
    );
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain('denyWrite');
  });

  it('passes when a prompt is allowed and applies no block', async () => {
    const p = prompting(['allow']);
    const result = await gateWriteTargets([target('write', join('out', 'a.txt'))], {
      ...policy({ allowWrite: [] }),
      prompt: p.prompt,
    });
    expect(result).toBeUndefined();
    expect(p.calls).toHaveLength(1);
    expect(p.calls[0]?.title).toContain('not in allowWrite');
  });

  it('blocks when a prompt is denied', async () => {
    const p = prompting(['deny']);
    const result = await gateWriteTargets([target('write', join('out', 'a.txt'))], {
      ...policy({ allowWrite: [] }),
      prompt: p.prompt,
    });
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain('not in allowWrite');
  });

  it('prompts again for ssh on a later call even after an allow', async () => {
    const p = prompting(['allow', 'allow']);
    const deps = { ...policy({ allowWrite: ['ssh://h/**'] }), prompt: p.prompt };
    await gateWriteTargets([target('write', 'ssh://h/x', 'ssh')], deps);
    await gateWriteTargets([target('write', 'ssh://h/x', 'ssh')], deps);
    expect(p.calls).toHaveLength(2);
  });

  it('returns no block for an empty target list', async () => {
    expect(await gateWriteTargets([], { ...policy(), prompt: async () => 'deny' })).toBeUndefined();
  });
});
