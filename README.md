# omp-landstrip

Sandboxed bash and file-write gating for omp (Oh My Pi): OS-level filesystem
and network confinement for model-driven shell execution, plus policy
enforcement on omp's native write tools, powered by the
[landstrip](https://github.com/landstrip/landstrip) sandbox.

## What it covers

The extension replaces omp's built-in `bash` tool with a sandboxed
equivalent (last-wins registration) and intercepts `!`/`!!` bang commands
the same way. Every shell command is executed under the landstrip sandbox
with a policy derived from your configuration; denials surface as tool
errors instead of silent escapes. omp's native `task` subagents inherit
the sandbox automatically because they consume the same tool registry.

omp's native file tools are gated through the `tool_call` extension event —
the native tools stay registered (no shadowing), and every `write`, `edit`,
and `ast_edit` dispatch is checked against the same `sandbox.json` policy
before it runs: `denyWrite` / `denyWriteAlways` patterns block outright
(including sqlite row and archive member writes, judged on their container
file), `allowWrite` covers the rest, and anything else raises the approval
prompt (headless runs block). `local://` plan drafts and `conflict://`
merge state are session-owned and always allowed; `ssh://` remote writes
and non-default `xd://` device dispatches prompt every time. This mirrors
upstream pi-landstrip's design. `read` remains ungated for now.

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

Sandboxed bash plus `write`/`edit`/`ast_edit` gating is the current surface;
`read`-side gating is on the roadmap. The `/landstrip` management commands
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
