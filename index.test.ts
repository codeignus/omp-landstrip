// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it, vi } from 'vitest';

vi.mock('@oh-my-pi/pi-coding-agent', () => {
  const agentDir = mkdtempSync(join(tmpdir(), 'omp-landstrip-agent-'));
  return {
    getAgentDir: () => agentDir,
    settings: {
      getShellConfig: () => ({ shell: process.env.SHELL || '/bin/sh', args: ['-lc'] }),
    },
  };
});

import extension from './index.ts';

describe('omp-landstrip bash registration', () => {
  it('registers a bash tool on the host API', () => {
    const tools: string[] = [];
    const pi = {
      registerTool(tool: { name: string }) {
        tools.push(tool.name);
      },
      on() {},
    };
    expect(() => extension(pi as never)).not.toThrow();
    expect(tools).toEqual(['bash']);
  });
});
