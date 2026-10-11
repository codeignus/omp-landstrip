// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { describe, expect, it } from 'vitest';

import { extractWriteTargets, GATED_WRITE_TOOLS } from './write-targets.ts';

describe('extractWriteTargets', () => {
  it('extracts a plain filesystem write path and ignores content', () => {
    expect(extractWriteTargets('write', { path: 'src/a.ts', content: 'x' })).toEqual([
      { tool: 'write', raw: 'src/a.ts', path: 'src/a.ts', kind: 'fs' },
    ]);
  });

  it('unwraps a [path#TAG] write wrapper and peels raw selectors from URL targets', () => {
    expect(extractWriteTargets('write', { path: '[src/a.ts#AB12]', content: '' })).toEqual([
      { tool: 'write', raw: '[src/a.ts#AB12]', path: 'src/a.ts', kind: 'fs' },
    ]);
    expect(extractWriteTargets('write', { path: 'ssh://host/f:raw', content: '' })).toEqual([
      { tool: 'write', raw: 'ssh://host/f:raw', path: 'ssh://host/f', kind: 'ssh' },
    ]);
  });

  it('keeps a line-range write path verbatim so the tool raises its own error', () => {
    const targets = extractWriteTargets('write', { path: 'src/a.ts:1-5', content: '' });
    expect(targets).toHaveLength(1);
    expect(targets[0]?.kind).toBe('fs');
  });

  it('classifies xd:// device writes with their device name', () => {
    expect(extractWriteTargets('write', { path: 'xd://lsp', content: '{}' })).toEqual([
      { tool: 'write', raw: 'xd://lsp', path: 'xd://lsp', kind: 'xd', device: 'lsp' },
    ]);
    expect(extractWriteTargets('write', { path: 'xd://', content: '{}' })).toEqual([
      { tool: 'write', raw: 'xd://', path: 'xd://', kind: 'xd', device: '' },
    ]);
  });

  it('classifies ssh:// targets including list smuggling, never as internal', () => {
    expect(extractWriteTargets('write', { path: 'ssh://host/x', content: '' })[0]?.kind).toBe(
      'ssh',
    );
    expect(
      extractWriteTargets('ast_edit', {
        ops: [{ pat: 'a', out: 'b' }],
        paths: ['a.ts,ssh://h/x'],
      })[0]?.kind,
    ).toBe('ssh');
  });

  it('classifies internal URL schemes with their scheme', () => {
    expect(extractWriteTargets('write', { path: 'local://a.md', content: '' })).toEqual([
      {
        tool: 'write',
        raw: 'local://a.md',
        path: 'local://a.md',
        kind: 'internal',
        scheme: 'local',
      },
    ]);
    expect(extractWriteTargets('write', { path: 'vault://n.md', content: '' })).toEqual([
      {
        tool: 'write',
        raw: 'vault://n.md',
        path: 'vault://n.md',
        kind: 'internal',
        scheme: 'vault',
      },
    ]);
    expect(extractWriteTargets('write', { path: 'conflict://7', content: '' })).toEqual([
      {
        tool: 'write',
        raw: 'conflict://7',
        path: 'conflict://7',
        kind: 'internal',
        scheme: 'conflict',
      },
    ]);
  });

  it('keeps sqlite-style container paths as fs for the probing gate', () => {
    expect(extractWriteTargets('write', { path: 'db.sqlite:rows:1', content: '{}' })[0]?.kind).toBe(
      'fs',
    );
  });

  it('extracts the replace-mode edit path', () => {
    expect(extractWriteTargets('edit', { path: 'a.ts', find: 'x', replace: 'y' })).toEqual([
      { tool: 'edit', raw: 'a.ts', path: 'a.ts', kind: 'fs' },
    ]);
  });

  it('dedupes hashline edit targets when path and paths overlap', () => {
    const input = { input: '¶a.ts#AB12\n+x', path: 'a.ts', paths: ['a.ts'] };
    expect(extractWriteTargets('edit', input)).toEqual([
      { tool: 'edit', raw: 'a.ts', path: 'a.ts', kind: 'fs' },
    ]);
  });

  it('extracts every path from a multi-file hashline edit', () => {
    const input = { input: '¶a.ts#AB12\n+x\n¶lib/b.ts#CD34\n-y', paths: ['a.ts', 'lib/b.ts'] };
    expect(extractWriteTargets('edit', input).map((t) => t.path)).toEqual(['a.ts', 'lib/b.ts']);
  });

  it('fails closed with an unknown target when edit has no extractable path', () => {
    expect(extractWriteTargets('edit', { input: '+ x' })).toEqual([
      { tool: 'edit', raw: '', path: '', kind: 'unknown' },
    ]);
    expect(extractWriteTargets('write', {})).toEqual([
      { tool: 'write', raw: '', path: '', kind: 'unknown' },
    ]);
  });

  it('extracts ast_edit paths verbatim, skipping non-strings', () => {
    const targets = extractWriteTargets('ast_edit', {
      ops: [{ pat: 'a', out: 'b' }],
      paths: ['src/**/*.ts', 'b.ts', 42],
    });
    expect(targets.map((t) => t.path)).toEqual(['src/**/*.ts', 'b.ts']);
    expect(targets.every((t) => t.kind === 'fs')).toBe(true);
  });

  it('returns no targets for ungated tools or missing input', () => {
    expect(extractWriteTargets('read', { path: 'a.ts' })).toEqual([]);
    expect(extractWriteTargets('write', undefined)).toEqual([]);
    expect(GATED_WRITE_TOOLS['ast_edit']).toBe(true);
  });
});
