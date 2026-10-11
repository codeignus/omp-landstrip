// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

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

type ToolCallHandler = (
  event: { type: 'tool_call'; toolName: string; toolCallId: string; input: unknown },
  ctx: Record<string, unknown>,
) => Promise<{ block: true; reason: string } | undefined>;

function createPi() {
  const handlers: Record<string, (...args: never[]) => unknown> = {};
  const tools: string[] = [];
  return {
    tools,
    handlers,
    registerTool(tool: { name: string }) {
      tools.push(tool.name);
    },
    on(event: string, handler: (...args: never[]) => unknown) {
      handlers[event] = handler;
    },
  };
}

function projectCwd(filesystem: Record<string, unknown>): string {
  const cwd = mkdtempSync(join(tmpdir(), 'omp-landstrip-project-'));
  mkdirSync(join(cwd, '.omp'), { recursive: true });
  writeFileSync(join(cwd, '.omp', 'sandbox.json'), JSON.stringify({ filesystem }), 'utf-8');
  return cwd;
}

function contextFor(cwd: string, ui?: Record<string, unknown>): Record<string, unknown> {
  return {
    cwd,
    hasUI: ui !== undefined,
    isProjectTrusted: () => true,
    mode: undefined,
    ui: ui ?? {},
  };
}

async function startSession(
  handlers: Record<string, (...args: never[]) => unknown>,
  cwd: string,
  ui?: Record<string, unknown>,
) {
  await handlers['session_start']!(undefined as never, contextFor(cwd, ui) as never);
}

describe('omp-landstrip bash registration', () => {
  it('registers a bash tool on the host API', () => {
    const pi = createPi();
    expect(() => extension(pi as never)).not.toThrow();
    expect(pi.tools).toEqual(['bash']);
  });
});

describe('omp-landstrip tool_call write gating', () => {
  const projects: string[] = [];

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('registers a tool_call handler', () => {
    const pi = createPi();
    extension(pi as never);
    expect(typeof pi.handlers['tool_call']).toBe('function');
  });

  it('passes through ungated tools and sandboxed bash events', async () => {
    const pi = createPi();
    extension(pi as never);
    const cwd = projectCwd({});
    projects.push(cwd);
    await startSession(pi.handlers, cwd);
    const handler = pi.handlers['tool_call'] as unknown as ToolCallHandler;
    expect(
      await handler(
        { type: 'tool_call', toolName: 'bash', toolCallId: '1', input: { command: 'ls' } },
        contextFor(cwd),
      ),
    ).toBeUndefined();
    expect(
      await handler(
        { type: 'tool_call', toolName: 'read', toolCallId: '2', input: { path: 'a.ts' } },
        contextFor(cwd),
      ),
    ).toBeUndefined();
  });

  it('blocks writes matched by the default denyWrite policy', async () => {
    const pi = createPi();
    extension(pi as never);
    const cwd = projectCwd({});
    projects.push(cwd);
    await startSession(pi.handlers, cwd);
    const handler = pi.handlers['tool_call'] as unknown as ToolCallHandler;
    const result = await handler(
      {
        type: 'tool_call',
        toolName: 'write',
        toolCallId: '3',
        input: { path: join(cwd, '.env'), content: 'X=1' },
      },
      contextFor(cwd),
    );
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain('denyWrite');
  });

  it('blocks writes matched by project denyWrite and passes allowed project paths', async () => {
    const pi = createPi();
    extension(pi as never);
    const cwd = projectCwd({ denyWrite: ['**/blocked/**'] });
    projects.push(cwd);
    await startSession(pi.handlers, cwd);
    const handler = pi.handlers['tool_call'] as unknown as ToolCallHandler;
    const blocked = await handler(
      {
        type: 'tool_call',
        toolName: 'write',
        toolCallId: '4',
        input: { path: join(cwd, 'blocked', 'x.txt'), content: '' },
      },
      contextFor(cwd),
    );
    expect(blocked?.block).toBe(true);
    const allowed = await handler(
      {
        type: 'tool_call',
        toolName: 'edit',
        toolCallId: '5',
        input: { path: join(cwd, 'src', 'a.ts') },
      },
      contextFor(cwd),
    );
    expect(allowed).toBeUndefined();
  });

  it('blocks un-allowlisted writes without a UI instead of running silently', async () => {
    const pi = createPi();
    extension(pi as never);
    const cwd = projectCwd({});
    projects.push(cwd);
    await startSession(pi.handlers, cwd);
    const handler = pi.handlers['tool_call'] as unknown as ToolCallHandler;
    const outside = join(tmpdir(), 'omp-landstrip-outside', 'x.txt');
    const result = await handler(
      {
        type: 'tool_call',
        toolName: 'write',
        toolCallId: '6',
        input: { path: outside, content: '' },
      },
      contextFor(cwd),
    );
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain('not in allowWrite');
  });

  it('remembers a session allow choice and stops prompting', async () => {
    const pi = createPi();
    extension(pi as never);
    const cwd = projectCwd({});
    projects.push(cwd);
    const select = vi.fn(async () => 'Allow for this session');
    const ui = {
      select,
      notify: () => undefined,
      setStatus: () => undefined,
      theme: { fg: (_color: string, text: string) => text },
    };
    await startSession(pi.handlers, cwd, ui);
    const handler = pi.handlers['tool_call'] as unknown as ToolCallHandler;
    const outside = join(tmpdir(), 'omp-landstrip-session', 'x.txt');
    const first = await handler(
      {
        type: 'tool_call',
        toolName: 'write',
        toolCallId: '7',
        input: { path: outside, content: '' },
      },
      contextFor(cwd, ui),
    );
    expect(first).toBeUndefined();
    const second = await handler(
      {
        type: 'tool_call',
        toolName: 'write',
        toolCallId: '8',
        input: { path: outside, content: '' },
      },
      contextFor(cwd, ui),
    );
    expect(second).toBeUndefined();
    expect(select).toHaveBeenCalledTimes(1);
  });

  it('allows default xd:// devices without prompting', async () => {
    const pi = createPi();
    extension(pi as never);
    const cwd = projectCwd({});
    projects.push(cwd);
    await startSession(pi.handlers, cwd);
    const handler = pi.handlers['tool_call'] as unknown as ToolCallHandler;
    const result = await handler(
      {
        type: 'tool_call',
        toolName: 'write',
        toolCallId: '9',
        input: { path: 'xd://report_issue', content: '{}' },
      },
      contextFor(cwd),
    );
    expect(result).toBeUndefined();
  });
});
