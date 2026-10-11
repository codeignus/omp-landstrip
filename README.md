# omp-landstrip

Sandboxed bash tool for omp (Oh My Pi): OS-level filesystem and network
confinement for model-driven shell execution, powered by the
[landstrip](https://github.com/landstrip/landstrip) sandbox.

## What it covers

The extension replaces omp's built-in `bash` tool with a sandboxed
equivalent (last-wins registration) and intercepts `!`/`!!` bang commands
the same way. Every shell command is executed under the landstrip sandbox
with a policy derived from your configuration; denials surface as tool
errors instead of silent escapes. omp's native `task` subagents inherit
the sandbox automatically because they consume the same tool registry.

omp's own file tools (`read`, `write`, `edit`, ...) are host-native and are
not gated by this package.

## Install

From a checkout:

    omp install ./path/to/omp-landstrip
    # or per run:
    omp -e ./path/to/omp-landstrip/dist/index.ts

From npm once published:

    omp install omp-landstrip

## Configuration

Policy lives in `sandbox.json`. The global file `~/.omp/agent/sandbox.json`
is created empty (`{}`) on first run; a project-local `.omp/sandbox.json`
deep-merges over it. Package defaults sit underneath both. Key fields:

- `enabled` — turn the sandbox on or off.
- `shell.readAccess` — `"host"` (shell may read the host) or `"policy"`
  (reads gated by the lists below).
- `filesystem.allowWrite` / `denyWrite` — write allowlist and deny
  patterns (globs, `**` supported); `allowRead` / `denyRead` apply when
  `readAccess` is `"policy"`.
- `filesystem.denyWriteAlways` / `denyReadAlways` — deny patterns that
  approvals can never widen.
- `network.allowNetwork` — when `false`, HTTP(S) egress is routed through
  a filtering proxy: `allowedDomains` is the allowlist, `deniedDomains`
  always blocks, unlisted domains raise a prompt (headless runs block).
- `windows.*` — AppContainer options on Windows.

When a sandboxed command hits a denial, the TUI offers to allow it once,
for the session, for the project, or everywhere; approvals widen the
session policy and may persist to the config file. `deny*Always` patterns
are never bypassable, and commands never run unsandboxed — if the sandbox
cannot start, bash fails closed.

## Scope

Sandboxed bash is the initial surface. The `/landstrip` management commands
and dashboard pane known from pi-landstrip are not ported; the worker-based
subagent system is intentionally omitted — omp's native `task` system is
used instead and runs under the same sandboxed bash.

## Requirements

omp 18.x (verified against 18.4.12) and Node.js >= 22.19. The landstrip
sandbox binary is pulled in automatically as a platform package of
`@landstrip/landstrip-api`.

## Attribution

This package is derived from
[pi-landstrip](https://github.com/landstrip/landstrip/tree/main/packages/pi-landstrip)
at commit `68316cec` (Apache-2.0), imported and modified for omp. Files in
this repository have been changed from the original; consult the git history
for the modifications. The original copyright notice and license are
retained — see [LICENSE](LICENSE).
