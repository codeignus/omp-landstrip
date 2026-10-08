// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { type ChildProcess, spawn, spawnSync, type StdioOptions } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { type AddressInfo, createServer, Socket as NetSocket } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, parse, resolve } from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { fileURLToPath } from 'node:url';

import type { ExtensionAPI, ExtensionContext, ToolDefinition } from '@oh-my-pi/pi-coding-agent';
import { getAgentDir, settings } from '@oh-my-pi/pi-coding-agent';
import { Type } from '@oh-my-pi/omptype/typebox';
import {
  binaryPath,
  type LandstripControlResponse,
  type LandstripFilesystemTrap,
  type LandstripNetworkTrap,
  type LandstripPolicy,
  type SandboxConfig as BaseSandboxConfig,
  type SandboxConfigFile,
  type SandboxFilesystemConfig,
  type SandboxShellConfig,
  type SandboxWindowsConfig,
  type ShellReadAccess,
} from '@landstrip/landstrip-api';
import {
  buildLandstripPolicy as assembleLandstripPolicy,
  allowsAllDomains,
  controlResponseLine,
  deepMergeSandboxConfig as deepMerge,
  domainMatchesAny,
  evaluateDomainAccess,
  formatLandstripTraps,
  isDenialTrap,
  isFilesystemTrap,
  isPathReadAllowed,
  isRecord,
  isQueryTrap,
  matchesPathPattern,
  mergeArray,
  parseLandstripTraps,
  parseSandboxConfig,
  canonicalizeGlobPattern,
  canonicalizePath,
  expandPath,
  globToRegExp,
  normalizePathSeparators,
  parseTrapLine,
  pathUnderDirectory,
  sessionScopeFor,
  serializeLandstripPolicy,
  shouldPromptForWrite as sharedShouldPromptForWrite,
  normalizeBlockedPath,
  extractNativeDeniedPath,
  extractNativeWriteDeniedPath,
  extractDeniedPath,
  extractTrapBlockedPath,
} from '@landstrip/landstrip-api/shared';
import {
  type ProxyPortRange,
  createProxyCredentials,
  createProxyEnvironment,
  startFilterProxy,
} from '@landstrip/landstrip-api/proxy';

export {
  controlResponseLine,
  domainMatchesAny,
  extractDeniedPath,
  extractNativeDeniedPath,
  extractNativeWriteDeniedPath,
  formatLandstripTraps,
  isQueryTrap,
  parseTrapLine,
  sessionScopeFor,
  type ShellReadAccess,
};

export interface SandboxConfig extends BaseSandboxConfig {
  shell: SandboxShellConfig;
  windows: SandboxWindowsConfig;
}
import type {
  LandstripShellInvocation,
  LandstripShellPrepareOptions,
  LandstripShellProvider,
} from './api.ts';
import { getOmpConfigPaths } from './config.ts';
import { formatError, PermissionPromptCoordinator, withFileMutationQueue } from './util.ts';

export type SandboxConfigScope = 'global' | 'project';

export type PolicyAudience = 'shell' | 'worker';

export function enforcesShellReadPolicy(
  shellReadAccess: string,
  platform: NodeJS.Platform = process.platform,
): boolean {
  return shellReadAccess !== 'host' || platform === 'win32';
}

export function resolveProcessReadPolicy(
  audience: PolicyAudience,
  shellReadAccess: ShellReadAccess,
  denyRead: string[],
  allowRead: string[],
  platform: NodeJS.Platform = process.platform,
): Pick<SandboxFilesystemConfig, 'denyRead' | 'allowRead'> {
  if (audience === 'shell' && !enforcesShellReadPolicy(shellReadAccess, platform)) {
    return { denyRead: [], allowRead: [] };
  }
  return { denyRead, allowRead };
}

interface SandboxExecRequest {
  readonly command: string;
  readonly cwd: string;
  readonly onData: (data: Buffer) => void;
  readonly signal?: AbortSignal;
  readonly timeout?: number;
  readonly env?: NodeJS.ProcessEnv;
}

interface SandboxExecResult {
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly landstripErrorOutput: string;
  readonly cancelled: boolean;
  readonly timedOut: boolean;
}

interface ExecutionAllowances {
  readonly permissionPromptLabel?: string;
  // Present only for worker launches; never let a broker approve these rules.
  explicitDenyRead?: { patterns: string[]; globRoots: Map<string, string[]> };
  readonly protectedPaths?: string[];
  readonly domains: string[];
  readonly readPaths: string[];
  readonly writePaths: string[];
  readonly targets: string[];
}

const SUPPORTED_PLATFORMS = new Set<NodeJS.Platform>(['linux', 'darwin', 'win32']);
// Grace period after the child exits for its stdio to drain before we stop
// waiting; matches pi's own bash backend so a backgrounded process cannot hang us.
const EXIT_STDIO_GRACE_MS = 100;

const packageDir = dirname(fileURLToPath(import.meta.url));
type PermissionChoice = 'abort' | 'once' | 'session' | 'project' | 'global';
type NotificationLevel = Parameters<ExtensionContext['ui']['notify']>[1];

interface PromptOption {
  label: string;
  action: PermissionChoice;
  confirm?: boolean;
  hint?: string;
}

const PERMISSION_OPTIONS: PromptOption[] = [
  { label: 'Allow once', action: 'once' },
  { label: 'Allow for this session', action: 'session' },
  {
    label: 'Allow for this project',
    action: 'project',
    confirm: true,
    hint: 'save to .omp/sandbox.json',
  },
  {
    label: 'Allow for all projects',
    action: 'global',
    confirm: true,
    hint: 'save to ~/.omp/agent/sandbox.json',
  },
  { label: 'Keep blocked', action: 'abort' },
];

const NETWORK_PERMISSION_OPTIONS: PromptOption[] = [
  { label: 'Allow once', action: 'once' },
  { label: 'Allow for this session', action: 'session' },
  { label: 'Keep blocked', action: 'abort' },
];

function loadSandboxConfig(
  cwd: string,
  includeProject: boolean,
): SandboxConfig & { explicitDenyRead: string[] } {
  const projectConfigPath = join(cwd, '.omp', 'sandbox.json');
  const globalConfigPath = join(getAgentDir(), 'sandbox.json');

  if (!existsSync(globalConfigPath)) {
    mkdirSync(dirname(globalConfigPath), { recursive: true });
    writeFileSync(globalConfigPath, '{}\n', 'utf-8');
  }

  const globalOverrides = readOrEmptyConfig(globalConfigPath);
  const projectOverrides = includeProject ? readOrEmptyConfig(projectConfigPath) : {};
  const globalConfig = deepMerge(
    JSON.parse(readFileSync(join(packageDir, 'sandbox.json'), 'utf-8')),
    globalOverrides,
  );

  return {
    ...deepMerge(globalConfig, projectOverrides),
    // Persisted rules are explicit, even when identical to an internal default.
    explicitDenyRead: mergeArray(
      globalOverrides.filesystem?.denyRead ?? [],
      projectOverrides.filesystem?.denyRead,
    ),
  };
}

type WindowsImplementation = 'appContainer' | 'restrictedUser';

interface WindowsStatus {
  active: WindowsImplementation;
  installed: boolean;
  healthy: boolean;
  proxyPortLow?: number;
  proxyPortHigh?: number;
}

function windowsStatus(): WindowsStatus {
  const result = spawnSync(binaryPath(), ['windows', 'status'], {
    encoding: 'utf-8',
    windowsHide: true,
  });
  if (result.error) throw result.error;

  let status: WindowsStatus;
  try {
    status = JSON.parse(result.stdout) as WindowsStatus;
  } catch {
    throw new Error(result.stderr.trim() || 'Windows sandbox status check failed');
  }
  if (result.status !== 0 || status.healthy !== true) {
    throw new Error(
      result.stderr.trim() ||
        'The Windows restricted-user installation is unhealthy. Run "landstrip windows status".',
    );
  }
  return status;
}

function shouldStartProxy(config: SandboxConfig): boolean {
  if (config.network.allowNetwork) return false;
  return (
    process.platform !== 'win32' ||
    windowsStatus().active === 'restrictedUser' ||
    config.windows.allowLoopback
  );
}

function restrictedUserProxyPortRange(): ProxyPortRange | undefined {
  if (process.platform !== 'win32') return undefined;

  const status = windowsStatus();
  if (status.active === 'appContainer') return undefined;
  if (
    status.installed !== true ||
    !Number.isInteger(status.proxyPortLow) ||
    !Number.isInteger(status.proxyPortHigh) ||
    status.proxyPortLow! < 1 ||
    status.proxyPortHigh! < status.proxyPortLow!
  ) {
    throw new Error(
      'The Windows restricted-user installation is unhealthy. Run "landstrip windows status".',
    );
  }
  return { low: status.proxyPortLow!, high: status.proxyPortHigh! };
}

function readOrEmptyConfig(configPath: string): SandboxConfigFile {
  if (!existsSync(configPath)) return {};
  try {
    return parseSandboxConfig(JSON.parse(readFileSync(configPath, 'utf-8')));
  } catch (error) {
    throw new Error(`${configPath}: ${formatError(error)}`);
  }
}

function writeConfigFile(configPath: string, config: SandboxConfigFile): void {
  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`, 'utf-8');
}

function getSandboxConfigWriteTarget(
  cwd: string,
  includeProject = true,
): { scope: SandboxConfigScope; path: string } {
  const { globalPath, projectPath } = getOmpConfigPaths(cwd, 'sandbox.json');
  return includeProject
    ? { scope: 'project', path: projectPath }
    : { scope: 'global', path: globalPath };
}

async function writeSandboxConfigEnabled(
  cwd: string,
  enabled: boolean | undefined,
  scope: SandboxConfigScope,
): Promise<void> {
  const paths = getOmpConfigPaths(cwd, 'sandbox.json');
  const path = scope === 'project' ? paths.projectPath : paths.globalPath;
  await withFileMutationQueue(path, async () => {
    const config = readOrEmptyConfig(path);
    if (enabled === undefined) delete config.enabled;
    else config.enabled = enabled;
    writeConfigFile(path, config);
  });
}

function loadSandboxEnabledSettings(
  cwd: string,
  includeProject: boolean,
): { global: boolean; project?: boolean } {
  const { projectPath } = getOmpConfigPaths(cwd, 'sandbox.json');
  const global = loadSandboxConfig(cwd, false).enabled;
  if (!includeProject || !existsSync(projectPath)) return { global };
  const project = readOrEmptyConfig(projectPath).enabled;
  return { global, project };
}

async function addConfigValue(
  configPath: string,
  value: string,
  readValues: (config: SandboxConfigFile) => string[],
  writeValues: (config: SandboxConfigFile, values: string[]) => void,
): Promise<void> {
  await withFileMutationQueue(configPath, async () => {
    const config = readOrEmptyConfig(configPath);
    const existing = readValues(config);
    if (existing.includes(value)) return;
    writeValues(config, [...existing, value]);
    writeConfigFile(configPath, config);
  });
}

function mergeAllowances(base: string[], session: string[], execution?: string[]): string[] {
  return [...base, ...session, ...(execution ?? [])];
}

export function shouldPromptForWrite(path: string, allowWrite: string[], cwd: string): boolean {
  return sharedShouldPromptForWrite(path, allowWrite, cwd);
}

export function matchesPattern(
  filePath: string,
  patterns: string[],
  cwd: string,
  explicitDenyGlobRoots?: Map<string, string[]>,
): boolean {
  if (!explicitDenyGlobRoots) {
    return matchesPathPattern(filePath, patterns, cwd);
  }
  const abs = normalizePathSeparators(canonicalizePath(filePath, cwd));

  return patterns.some((pattern) => {
    const absPattern = normalizePathSeparators(canonicalizeGlobPattern(pattern, cwd));

    if (/[*?[\]]/.test(pattern)) {
      // Mirror landstrip's matcher: `**/` spans directories, `**` spans any run,
      // but a single `*` stops at `/` — so `/srv/*/pub` cannot reach
      // `/srv/a/secret/pub`. Compiling `*` to `.*` would over-match across `/`.
      const matcher = globToRegExp(absPattern);
      // Native glob matches name directory roots as well as files. Descendants
      // inherit the matched directory's rule, including paths not created yet.
      for (let candidate = abs; ;) {
        if (matcher.test(candidate)) return true;
        const parent = normalizePathSeparators(dirname(candidate));
        if (parent === candidate) break;
        candidate = parent;
      }

      // Only explicit worker denies need native glob lowering. Retain the
      // canonical roots per worker so trap queries never repeat the traversal.
      if (!explicitDenyGlobRoots) return false;
      let roots = explicitDenyGlobRoots.get(absPattern);
      if (!roots) {
        const resolvedRoots: string[] = [];
        const wildcard = absPattern.search(/[*?[\]]/);
        const base = absPattern.slice(0, absPattern.lastIndexOf('/', wildcard) + 1);
        const suffix = absPattern.slice(base.length);
        const segments = suffix.match(/(?:\[[^\]]*\]|[^/])+/g) ?? [];
        const recursive = suffix.includes('**');
        const visit = (directory: string, depth: number): void => {
          if (depth >= 40) throw new Error(`Glob traversal depth exceeded for "${pattern}"`);
          let entries;
          try {
            entries = readdirSync(directory, { withFileTypes: true });
          } catch (error) {
            if (
              isRecord(error) &&
              ['ENOENT', 'ENOTDIR', 'EACCES', 'EPERM'].includes(String(error.code))
            ) {
              return;
            }
            throw error;
          }
          for (const entry of entries) {
            const candidate = normalizePathSeparators(join(directory, entry.name));
            // Match the alias before canonicalizing: `/runtime/ali*` can lower
            // to a root such as `/opt/worker` that does not match lexically.
            if (entry.isSymbolicLink() && matcher.test(candidate)) {
              resolvedRoots.push(normalizePathSeparators(canonicalizePath(candidate, cwd)));
            }
            // Like native expansion, never descend through a symlink. Without
            // globstars, prune directories that cannot match the next segment.
            if (
              entry.isDirectory() &&
              (recursive ||
                (depth + 1 < segments.length && globToRegExp(segments[depth]!).test(entry.name)))
            ) {
              visit(candidate, depth + 1);
            }
          }
        };
        visit(base, 0);
        roots = resolvedRoots;
        explicitDenyGlobRoots.set(absPattern, roots);
      }
      return roots.some(
        (target) => abs === target || abs.startsWith(target.endsWith('/') ? target : `${target}/`),
      );
    }

    const sep = absPattern.endsWith('/') ? '' : '/';
    return abs === absPattern || abs.startsWith(absPattern + sep);
  });
}

export function readAllowed(
  path: string,
  allowRead: string[],
  denyRead: string[],
  cwd: string,
): boolean {
  return isPathReadAllowed(path, allowRead, denyRead, cwd);
}

function extractDeniedPathMention(
  output: string,
  cwd: string,
  denied: (path: string) => boolean,
): string | null {
  const start = /(?<=^|['"`\s=:(])(?=\/|[a-zA-Z]:[\\/])/g;
  for (const line of output.split(/\r?\n/)) {
    for (const match of line.matchAll(start)) {
      const raw = line.slice(match.index);
      const quoted = raw.match(/^([^'"`]+)['"`]/);
      const words = (quoted ? quoted[1] : raw).replace(/[.,:;)\]]+$/, '').split(' ');
      for (let count = words.length; count > 0; count -= 1) {
        const candidate = words.slice(0, count).join(' ');
        if (!existsSync(candidate)) continue;
        const path = normalizeBlockedPath(candidate, cwd);
        if (denied(path)) return path;
        break;
      }
    }
  }
  return null;
}

export function extractRetryableNativeReadDeniedPath(
  output: string,
  cwd: string,
  allowRead: string[],
  denyRead: string[],
): string | null {
  const denied = (path: string): boolean => !readAllowed(path, allowRead, denyRead, cwd);
  const path = extractNativeDeniedPath(output, cwd);
  if (path) return denied(path) ? path : null;
  return extractDeniedPathMention(output, cwd, denied);
}

function notify(ctx: ExtensionContext, message: string, level: NotificationLevel): void {
  if (!ctx.hasUI) return;
  ctx.ui.notify(message, level);
}

function hasTuiStatus(ctx: ExtensionContext): boolean {
  if (!ctx.hasUI) return false;
  const mode = ctx.mode;
  return mode === undefined || mode === 'tui';
}

function setTuiStatus(ctx: ExtensionContext, key: string, value: string | undefined): void {
  if (!hasTuiStatus(ctx)) return;
  ctx.ui.setStatus(key, value);
}

function patchProcessGroupKill(child: ChildProcess): void {
  const kill = child.kill.bind(child);
  child.kill = (signal?: NodeJS.Signals | number): boolean => {
    if (signal === 0 || child.pid === undefined) return kill(signal);
    if (process.platform === 'win32') {
      const result = spawnSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], {
        stdio: 'ignore',
        windowsHide: true,
      });
      if (result.status === 0) return true;
    } else {
      try {
        process.kill(-child.pid, signal);
        return true;
      } catch {
        // Fall back when the process exited before its group was signalled.
      }
    }
    return kill(signal);
  };
}

async function showPermissionPrompt(
  ctx: ExtensionContext,
  title: string,
  options: PromptOption[],
  signal?: AbortSignal,
  label?: string,
): Promise<PermissionChoice> {
  if (!ctx.hasUI) return 'abort';

  const labels = options.map((option) =>
    option.hint ? `${option.label} — ${option.hint}` : option.label,
  );
  const selected = await ctx.ui.select(label ? `${label}\n${title}` : title, labels, { signal });
  if (signal?.aborted) return 'abort';
  const index = selected === undefined ? -1 : labels.indexOf(selected);
  const option = options[index];
  if (!option) return 'abort';
  if (option.confirm) {
    const confirmed = await ctx.ui.confirm(
      label ? `${label}\nSave this permission?` : 'Save this permission?',
      `${title}\n\n${option.hint ?? 'This changes persisted sandbox policy.'}`,
      { signal },
    );
    if (!confirmed || signal?.aborted) return 'abort';
  }
  return option.action;
}

function promptReadBlock(
  ctx: ExtensionContext,
  filePath: string,
  reason?: string,
  signal?: AbortSignal,
  label?: string,
): Promise<PermissionChoice> {
  const title = reason
    ? `Read blocked: "${filePath}" is in denyRead (${reason})`
    : `Read blocked: "${filePath}" is not in allowRead`;
  return showPermissionPrompt(ctx, title, PERMISSION_OPTIONS, signal, label);
}

// Write the full environment to a temporary shell file.
//
// Sandboxed process reaches environment through the filesystem instead of the
// execve() argument buffer, which has a ~128 KiB cap.
export function writeEnvFile(
  env: NodeJS.ProcessEnv,
  proxyPort: number | null,
  proxyToken?: string,
): { dir: string; path: string } {
  const lines: string[] = [];
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) continue;
    // bash exports non-identifier names (e.g. a `BASH_FUNC_foo%%` function
    // export) that `export NAME=...` rejects; emitting one makes `source` exit
    // non-zero and the `&&`-chained command never runs. Skip what the shell
    // itself cannot set.
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    // Escape single quotes: ' -> '\''
    const escaped = value.replace(/'/g, "'\\''");
    lines.push(`export ${key}='${escaped}'`);
  }
  if (proxyPort !== null) {
    const proxyVars = createProxyEnvironment(proxyPort, proxyToken);
    for (const [name, value] of Object.entries(proxyVars)) {
      lines.push(`export ${name}='${value}'`);
    }
  }
  const dir = mkdtempSync(join(tmpdir(), 'pi-landstrip-env-'));
  const path = join(dir, 'env.sh');
  writeFileSync(path, lines.join('\n'), 'utf-8');
  return { dir, path };
}

export const POSIX_SHELL_PROVIDER_ID = 'posix';

function resolvePosixShell(): { shell: string; args: readonly string[] } {
  try {
    const config = settings.getShellConfig();
    return { shell: config.shell, args: config.args };
  } catch {
    if (process.platform === 'win32') {
      return {
        shell: join(process.env.ProgramFiles ?? 'C:\\Program Files', 'Git', 'bin', 'bash.exe'),
        args: ['-lc'],
      };
    }
    return { shell: process.env.SHELL || '/bin/sh', args: ['-lc'] };
  }
}

export function createPosixShellProvider(): LandstripShellProvider {
  return {
    id: POSIX_SHELL_PROVIDER_ID,
    prepare(options: LandstripShellPrepareOptions): LandstripShellInvocation {
      if (options.signal?.aborted) throw new Error('aborted');
      const { shell, args } = resolvePosixShell();
      const envFile = writeEnvFile(options.env, null);
      let disposed = false;

      return {
        executable: shell,
        args: [...args, `source '${envFile.path}' && ${options.command}`],
        launcherEnv: { PATH: process.env.PATH, HOME: process.env.HOME },
        readPaths: [envFile.path],
        dispose() {
          if (disposed) return;
          disposed = true;
          rmSync(envFile.dir, { recursive: true, force: true });
        },
      };
    },
  };
}

function shellEnvironment(
  env: NodeJS.ProcessEnv | undefined,
  cwd: string,
  proxyPort: number | null,
  proxyToken?: string,
): NodeJS.ProcessEnv {
  const result: NodeJS.ProcessEnv = { ...process.env, ...env, PWD: resolve(cwd) };
  return createProxyEnvironment(proxyPort, proxyToken, result);
}

export function createLandstripLauncherEnvironment(
  providerEnv: NodeJS.ProcessEnv,
  hostEnv: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): NodeJS.ProcessEnv {
  if (platform !== 'win32' || hostEnv.ProgramData === undefined) return providerEnv;
  return { ...providerEnv, ProgramData: hostEnv.ProgramData };
}

export function createWindowsDenyRead(denyRead: readonly string[], volumeRoot: string): string[] {
  return [...new Set([...denyRead.filter((path) => !path.startsWith('/')), volumeRoot])];
}

/** Options for creating a landstrip sandbox integration. */
export interface LandstripIntegrationOptions {
  /** Register a sandboxed bash tool when the integration is registered. */
  readonly registerBashTool?: boolean;
  /** Working directory used when registering the default bash tool. */
  readonly cwd?: string;
}

export interface LandstripIntegration {
  /** Register the integration's tools and events with omp. */
  register(pi: ExtensionAPI): void;
  /** Return the active extension context, when a session is running. */
  getExtensionContext(): ExtensionContext | undefined;
  /** Callbacks for querying and toggling sandbox state. */
  readonly sandboxCallbacks?: SandboxCallbacks;
}

/** Callbacks for editing sandbox state from the agents dashboard. */
export interface SandboxCallbacks {
  load(cwd: string, includeProject: boolean): { global: boolean; project?: boolean };
  setEnabled(ctx: ExtensionContext, enabled: boolean, scope: SandboxConfigScope): Promise<void>;
  clearProject(ctx: ExtensionContext): Promise<void>;
  overview(cwd: string, includeProject: boolean): SandboxOverview;
}

/** Display data for the sandbox section of the settings pane. */
export interface SandboxOverview {
  readonly enabled: boolean;
  readonly running: boolean;
  readonly noSandboxFlag: boolean;
  readonly networkMode: 'unrestricted' | 'blocked' | 'proxied';
  readonly shellReadMode: 'host' | 'policy';
  readonly readRuleScope: string;
  readonly windowsMode?: string;
  readonly changeScope: SandboxConfigScope;
  readonly paths: { readonly global: string; readonly project: string; readonly binary: string };
  readonly config: SandboxConfig;
  readonly sessionDomains: readonly string[];
  readonly sessionReadPaths: readonly string[];
  readonly sessionWritePaths: readonly string[];
}

/** Register the landstrip extension with omp. */
export default function (pi: ExtensionAPI) {
  createLandstripIntegration().register(pi);
}

/** Create a landstrip integration for registration or custom embedding. */
export function createLandstripIntegration(
  options: LandstripIntegrationOptions = {},
): LandstripIntegration {
  return createLandstripIntegrationWithPrompts(options, new PermissionPromptCoordinator());
}

function createLandstripIntegrationWithPrompts(
  options: LandstripIntegrationOptions,
  permissionPrompts: PermissionPromptCoordinator,
): LandstripIntegration {
  const shouldRegisterBashTool = options.registerBashTool ?? true;
  let projectConfigTrusted = false;

  function loadConfig(cwd: string): ReturnType<typeof loadSandboxConfig> {
    return loadSandboxConfig(cwd, projectConfigTrusted);
  }

  let sandboxEnabled = false;
  let sandboxReady = false;
  const shellProvider = createPosixShellProvider();
  let sandboxState: 'enabled' | 'disabled' | 'unavailable' = 'unavailable';
  let activeContext: ExtensionContext | undefined;
  const sessionAllowedDomains: string[] = [];
  const sessionAllowedReadPaths: string[] = [];
  const sessionAllowedWritePaths: string[] = [];
  const sessionAllowedTargets: string[] = [];
  function getEffectiveAllowRead(
    config: SandboxConfig,
    cwd: string,
    allowances?: ExecutionAllowances,
  ): string[] {
    const paths = mergeAllowances(
      config.filesystem.allowRead,
      sessionAllowedReadPaths,
      allowances?.readPaths,
    );
    if (process.platform !== 'win32') return paths;

    return paths.filter(
      (path) => !path.startsWith('/') && (path.includes('*') || existsSync(expandPath(path, cwd))),
    );
  }

  function getEffectiveAllowWrite(
    config: SandboxConfig,
    allowances?: ExecutionAllowances,
  ): string[] {
    const paths = mergeAllowances(
      config.filesystem.allowWrite,
      sessionAllowedWritePaths,
      allowances?.writePaths,
    );
    return process.platform === 'win32' ? paths.filter((path) => !path.startsWith('/')) : paths;
  }

  function getEffectiveDenyRead(config: SandboxConfig, cwd: string): string[] {
    if (process.platform !== 'win32') return config.filesystem.denyRead;

    // Windows sandbox ACLs propagate to existing descendants, so make read policy
    // an explicit allowlist instead of scanning and granting a volume tree. Ignore
    // POSIX-only absolute paths because no corresponding ACL target exists.
    const volumeRoot = parse(resolve(cwd)).root;
    return createWindowsDenyRead(config.filesystem.denyRead, volumeRoot);
  }

  function hasBaselineWindowsApplicationAccess(filePath: string): boolean {
    const normalizedPath = normalizePathSeparators(resolve(filePath)).toLowerCase();
    const systemRoots = [
      process.env.ProgramFiles,
      process.env['ProgramFiles(x86)'],
      process.env.ProgramW6432,
      process.env.SystemRoot,
    ];

    return systemRoots.some((root) => {
      if (!root) return false;
      return pathUnderDirectory(
        normalizedPath,
        normalizePathSeparators(resolve(root)).toLowerCase(),
      );
    });
  }

  function withWindowsProcessReadAccess(
    allowances: ExecutionAllowances,
    command: string,
    cwd: string,
    additionalPaths: string[] = [],
  ): ExecutionAllowances {
    if (process.platform !== 'win32') return allowances;

    const executable = resolve(cwd, command);
    // Both standard AppContainers and restricted-user tokens receive baseline
    // read/execute access to Windows and Program Files through ALL APPLICATION
    // PACKAGES. Adding a sandbox-specific ACE there requires elevated WRITE_DAC.
    const executablePaths = hasBaselineWindowsApplicationAccess(executable) ? [] : [executable];
    return {
      ...allowances,
      readPaths: [...new Set([...allowances.readPaths, ...executablePaths, ...additionalPaths])],
    };
  }

  async function applyDomainChoice(
    choice: Exclude<PermissionChoice, 'abort'>,
    domain: string,
    cwd: string,
    allowances?: ExecutionAllowances,
  ): Promise<void> {
    const { globalPath, projectPath } = getOmpConfigPaths(cwd, 'sandbox.json');
    const configPath =
      choice === 'project' ? projectPath : choice === 'global' ? globalPath : undefined;
    if (configPath) {
      await addConfigValue(
        configPath,
        domain,
        (config) => config.network?.allowedDomains ?? [],
        (config, allowedDomains) => {
          config.network = {
            ...config.network,
            allowedDomains,
            deniedDomains: config.network?.deniedDomains ?? [],
          };
        },
      );
    }
    const target = choice === 'once' ? allowances?.domains : sessionAllowedDomains;
    if (target && !target.includes(domain)) target.push(domain);
  }

  // Breadth-first: approve the broadest reasonable ancestor of the blocked file
  // (see sessionScopeFor) instead of the exact path, so the still-running
  // command stops prompting for sibling files under the same tree. When the
  // scope widens beyond the file, tell the user what was actually granted.
  function noteScope(
    ctx: ExtensionContext,
    verb: string,
    choice: Exclude<PermissionChoice, 'abort'>,
    filePath: string,
    scope: string,
  ): void {
    if (scope !== filePath) notify(ctx, `${verb} allowed (${choice}): ${scope}`, 'info');
  }

  async function applyReadChoice(
    ctx: ExtensionContext,
    choice: Exclude<PermissionChoice, 'abort'>,
    filePath: string,
    cwd: string,
    allowances?: ExecutionAllowances,
  ): Promise<void> {
    const { globalPath, projectPath } = getOmpConfigPaths(cwd, 'sandbox.json');
    const scope = sessionScopeFor(filePath, cwd);
    const configPath =
      choice === 'project' ? projectPath : choice === 'global' ? globalPath : undefined;
    if (configPath) {
      await addConfigValue(
        configPath,
        scope,
        (config) => config.filesystem?.allowRead ?? [],
        (config, allowRead) => {
          config.filesystem = { ...config.filesystem, allowRead };
        },
      );
    }
    const target = choice === 'once' ? allowances?.readPaths : sessionAllowedReadPaths;
    if (target && !target.includes(scope)) target.push(scope);
    noteScope(ctx, 'Read', choice, filePath, scope);
  }

  async function applyWriteChoice(
    ctx: ExtensionContext,
    choice: Exclude<PermissionChoice, 'abort'>,
    filePath: string,
    cwd: string,
    allowances?: ExecutionAllowances,
  ): Promise<void> {
    const { globalPath, projectPath } = getOmpConfigPaths(cwd, 'sandbox.json');
    const scope = sessionScopeFor(filePath, cwd);
    const configPath =
      choice === 'project' ? projectPath : choice === 'global' ? globalPath : undefined;
    if (configPath) {
      await addConfigValue(
        configPath,
        scope,
        (config) => config.filesystem?.allowWrite ?? [],
        (config, allowWrite) => {
          config.filesystem = { ...config.filesystem, allowWrite };
        },
      );
    }
    const target = choice === 'once' ? allowances?.writePaths : sessionAllowedWritePaths;
    if (target && !target.includes(scope)) target.push(scope);
    noteScope(ctx, 'Write', choice, filePath, scope);
  }

  async function ensureDomainAllowed(
    ctx: ExtensionContext,
    domain: string,
    cwd: string,
    allowances?: ExecutionAllowances,
    signal?: AbortSignal,
  ): Promise<boolean> {
    const current = (): boolean | undefined => {
      const config = loadConfig(cwd);
      const decision = evaluateDomainAccess(domain, config.network, [
        ...sessionAllowedDomains,
        ...(allowances?.domains ?? []),
      ]);
      if (decision === 'deny') return false;
      if (decision === 'allow') return true;
      return undefined;
    };
    if (!ctx.hasUI) return current() ?? false;

    return permissionPrompts.resolve(
      current,
      async (promptSignal) => {
        const choice = await showPermissionPrompt(
          ctx,
          `Network blocked: "${domain}" is not in the allowed domains list`,
          PERMISSION_OPTIONS,
          promptSignal,
          allowances?.permissionPromptLabel,
        );
        if (choice === 'abort' || promptSignal.aborted) return false;
        await applyDomainChoice(choice, domain, cwd, allowances);
        return true;
      },
      signal,
    );
  }

  function buildLandstripPolicy(
    cwd: string,
    proxyPort: number | null,
    audience: PolicyAudience,
    allowances?: ExecutionAllowances,
  ): LandstripPolicy {
    const config = loadConfig(cwd);
    const readPolicy = resolveProcessReadPolicy(
      audience,
      config.shell.readAccess,
      mergeArray(getEffectiveDenyRead(config, cwd), [
        ...(allowances?.explicitDenyRead?.patterns ?? []),
        ...[...(allowances?.explicitDenyRead?.globRoots.values() ?? [])].flat(),
      ]),
      getEffectiveAllowRead(config, cwd, allowances),
    );

    return assembleLandstripPolicy({
      network: config.network,
      filesystem: {
        ...readPolicy,
        denyReadAlways: mergeArray(config.filesystem.denyReadAlways, allowances?.protectedPaths),
        allowWrite: getEffectiveAllowWrite(config, allowances),
        denyWrite: mergeArray(config.filesystem.denyWrite, allowances?.protectedPaths),
        denyWriteAlways: mergeArray(config.filesystem.denyWriteAlways, allowances?.protectedPaths),
      },
      windows: config.windows,
      httpProxyPort: proxyPort,
    });
  }

  function writePolicyFile(
    cwd: string,
    proxyPort: number | null,
    audience: PolicyAudience,
    allowances?: ExecutionAllowances,
  ): { dir: string; path: string } {
    const dir = mkdtempSync(join(tmpdir(), 'pi-landstrip-'));
    const path = join(dir, 'policy.json');
    writeFileSync(
      path,
      serializeLandstripPolicy(buildLandstripPolicy(cwd, proxyPort, audience, allowances)),
      'utf-8',
    );
    return { dir, path };
  }

  function startProxy(
    ctx: ExtensionContext,
    cwd: string,
    allowances: ExecutionAllowances,
    signal?: AbortSignal,
    authorization?: string,
    portRange?: ProxyPortRange,
  ): Promise<{ port: number; stop: () => Promise<void> }> {
    return startFilterProxy({
      isDomainAllowed: async (domain) => {
        const config = loadConfig(cwd);
        if (domainMatchesAny(domain, config.network.deniedDomains)) return false;
        return ensureDomainAllowed(ctx, domain, cwd, allowances, signal);
      },
      authorization,
      portRange,
    });
  }

  function createSocketPair(): Promise<[NetSocket, NetSocket]> {
    return new Promise((resolve, reject) => {
      const server = createServer();
      server.on('error', reject);
      let client: NetSocket | null = null;
      server.on('connection', (serverEnd) => {
        server.removeListener('error', reject);
        server.close();
        if (client) {
          client.removeListener('error', reject);
          resolve([client, serverEnd]);
        }
      });
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as AddressInfo;
        client = new NetSocket();
        client.on('error', reject);
        client.connect(addr.port, '127.0.0.1');
      });
    });
  }

  interface TrapQueryResult {
    action: LandstripControlResponse['action'];
    reason?: 'unprompted' | 'rejected' | 'hard-deny';
  }

  async function resolveTrapQuery(
    trap: LandstripFilesystemTrap | LandstripNetworkTrap,
    ctx: ExtensionContext,
    cwd: string,
    allowances: ExecutionAllowances,
    promptOnBlock: boolean,
    signal?: AbortSignal,
  ): Promise<TrapQueryResult> {
    // The broker knows only address:port, and no sandbox field can express a grant
    // for one non-loopback endpoint: allowedDomains is enforced by the proxy,
    // allowLocalBinding grants all loopback endpoints, and allowNetwork disables
    // network enforcement. So a non-loopback connection is granted for the session
    // or not at all.
    if (!isFilesystemTrap(trap)) {
      const key = `${trap.operation}\u0000${trap.target}`;
      const current = (): TrapQueryResult | undefined =>
        sessionAllowedTargets.includes(key) || allowances.targets.includes(key)
          ? { action: 'allow' }
          : undefined;
      const existing = current();
      if (existing) return existing;
      if (!ctx.hasUI || !promptOnBlock) return { action: 'deny', reason: 'unprompted' };

      return permissionPrompts.resolve(
        current,
        async (promptSignal) => {
          const choice = await showPermissionPrompt(
            ctx,
            `Network blocked: ${trap.operation} "${trap.target}"`,
            NETWORK_PERMISSION_OPTIONS,
            promptSignal,
            allowances.permissionPromptLabel,
          );
          if (choice === 'abort' || promptSignal.aborted)
            return { action: 'deny', reason: 'rejected' };
          const targets = choice === 'once' ? allowances.targets : sessionAllowedTargets;
          if (!targets.includes(key)) targets.push(key);
          return { action: 'allow' };
        },
        signal,
      );
    }

    const path = normalizeBlockedPath(trap.path, cwd);
    const current = (): TrapQueryResult | undefined => {
      if (matchesPattern(path, allowances.protectedPaths ?? [], cwd)) {
        return { action: 'deny', reason: 'hard-deny' };
      }
      const config = loadConfig(cwd);
      if (
        trap.operation === 'read' &&
        matchesPattern(path, config.filesystem.denyReadAlways, cwd)
      ) {
        return { action: 'deny', reason: 'hard-deny' };
      }
      if (
        trap.operation === 'read' &&
        allowances.explicitDenyRead &&
        matchesPattern(
          path,
          mergeArray(allowances.explicitDenyRead.patterns, config.explicitDenyRead),
          cwd,
          allowances.explicitDenyRead.globRoots,
        )
      ) {
        return { action: 'deny', reason: 'hard-deny' };
      }
      if (
        trap.operation === 'write' &&
        (matchesPattern(path, config.filesystem.denyWriteAlways, cwd) ||
          matchesPattern(path, config.filesystem.denyWrite, cwd))
      ) {
        return { action: 'deny', reason: 'hard-deny' };
      }
      const allowed =
        trap.operation === 'read'
          ? readAllowed(
              path,
              getEffectiveAllowRead(config, cwd, allowances),
              getEffectiveDenyRead(config, cwd),
              cwd,
            )
          : !shouldPromptForWrite(path, getEffectiveAllowWrite(config, allowances), cwd);
      return allowed ? { action: 'allow' } : undefined;
    };
    const existing = current();
    if (existing) return existing;
    if (!ctx.hasUI || !promptOnBlock) return { action: 'deny', reason: 'unprompted' };

    return permissionPrompts.resolve(
      current,
      async (promptSignal) => {
        const config = loadConfig(cwd);
        const choice =
          trap.operation === 'read'
            ? await promptReadBlock(
                ctx,
                path,
                matchesPattern(path, config.filesystem.denyRead, cwd)
                  ? 'granting allowRead will override it'
                  : undefined,
                promptSignal,
                allowances.permissionPromptLabel,
              )
            : await showPermissionPrompt(
                ctx,
                `Write blocked: "${path}" is not in allowWrite`,
                PERMISSION_OPTIONS,
                promptSignal,
                allowances.permissionPromptLabel,
              );
        if (choice === 'abort' || promptSignal.aborted)
          return { action: 'deny', reason: 'rejected' };
        if (trap.operation === 'read') {
          await applyReadChoice(ctx, choice, path, cwd, allowances);
        } else {
          await applyWriteChoice(ctx, choice, path, cwd, allowances);
        }
        return { action: 'allow' };
      },
      signal,
    );
  }

  async function executeSandboxed(
    ctx: ExtensionContext,
    request: SandboxExecRequest,
    promptOnBlock: boolean,
  ): Promise<SandboxExecResult> {
    const cwd = request.cwd;
    if (!existsSync(cwd)) throw new Error(`Working directory does not exist: ${cwd}`);

    const allowances: ExecutionAllowances = {
      domains: [],
      readPaths: [],
      writePaths: [],
      targets: [],
    };

    const run = () => executeSandboxedOnce(ctx, request, allowances, promptOnBlock);

    const blockedReadPathForRetry = (
      nativeOutput: string,
      landstripErrorOutput: string,
    ): string | null => {
      const config = loadConfig(cwd);
      if (!enforcesShellReadPolicy(config.shell.readAccess)) return null;
      const trappedPath = extractTrapBlockedPath(landstripErrorOutput, cwd, 'read');
      if (trappedPath) return trappedPath;
      return extractRetryableNativeReadDeniedPath(
        nativeOutput,
        cwd,
        getEffectiveAllowRead(config, cwd, allowances),
        getEffectiveDenyRead(config, cwd),
      );
    };

    const writeDenyTier = (blockedPath: string): 'denyWriteAlways' | 'denyWrite' | null => {
      const config = loadConfig(cwd);
      if (matchesPattern(blockedPath, config.filesystem.denyWriteAlways, cwd)) {
        return 'denyWriteAlways';
      }
      if (matchesPattern(blockedPath, config.filesystem.denyWrite, cwd)) return 'denyWrite';
      return null;
    };

    const retryWithAccess = async (
      operation: 'read' | 'write',
      blockedPath: string,
    ): Promise<SandboxExecResult | null> => {
      if (!ctx.hasUI) return null;
      const projectPath = join(cwd, '.omp', 'sandbox.json');
      const globalPath = join(getAgentDir(), 'sandbox.json');
      const current = (): boolean | undefined => {
        const config = loadConfig(cwd);
        if (operation === 'write' && writeDenyTier(blockedPath)) return false;
        if (
          operation === 'read' &&
          matchesPattern(blockedPath, config.filesystem.denyReadAlways, cwd)
        ) {
          return false;
        }
        const needsPrompt =
          operation === 'read'
            ? !readAllowed(
                blockedPath,
                getEffectiveAllowRead(config, cwd, allowances),
                getEffectiveDenyRead(config, cwd),
                cwd,
              )
            : shouldPromptForWrite(blockedPath, getEffectiveAllowWrite(config, allowances), cwd);
        return needsPrompt ? undefined : true;
      };
      const access = await permissionPrompts.resolve(
        current,
        async (promptSignal) => {
          const config = loadConfig(cwd);
          const choice =
            operation === 'read'
              ? await promptReadBlock(
                  ctx,
                  blockedPath,
                  matchesPattern(blockedPath, config.filesystem.denyRead, cwd)
                    ? 'granting allowRead will override it'
                    : undefined,
                  promptSignal,
                )
              : await showPermissionPrompt(
                  ctx,
                  `Write blocked: "${blockedPath}" is not in allowWrite`,
                  PERMISSION_OPTIONS,
                  promptSignal,
                );
          if (choice === 'abort' || promptSignal.aborted) return false;
          if (operation === 'read') {
            await applyReadChoice(ctx, choice, blockedPath, cwd, allowances);
          } else {
            await applyWriteChoice(ctx, choice, blockedPath, cwd, allowances);
          }
          return true;
        },
        request.signal,
      );
      if (!access) {
        const tier = operation === 'write' ? writeDenyTier(blockedPath) : null;
        if (tier) {
          notify(
            ctx,
            `"${blockedPath}" is blocked by ${tier}. Check:\n  ${projectPath}\n  ${globalPath}`,
            'warning',
          );
        }
        return null;
      }
      const tier = operation === 'write' ? writeDenyTier(blockedPath) : null;
      if (tier) {
        notify(
          ctx,
          `"${blockedPath}" was added to allowWrite, but ${tier} still blocks it. Check:\n  ${projectPath}\n  ${globalPath}`,
          'warning',
        );
        return null;
      }
      request.onData(
        Buffer.from(
          `\n--- ${operation === 'read' ? 'Read' : 'Write'} access granted for "${blockedPath}", retrying ---\n`,
        ),
      );
      return run();
    };

    let result: SandboxExecResult;
    try {
      result = await run();
    } catch (error) {
      const errorText = formatError(error);
      const fallbackOutput = `\n${errorText}`;
      const blockedWritePath = extractNativeWriteDeniedPath(fallbackOutput, cwd);
      if (blockedWritePath) {
        const retryResult = await retryWithAccess('write', blockedWritePath);
        if (retryResult) return retryResult;
      }
      const blockedReadPath = blockedReadPathForRetry(fallbackOutput, '');
      if (blockedReadPath) {
        const retryResult = await retryWithAccess('read', blockedReadPath);
        if (retryResult) return retryResult;
      }
      throw error;
    }

    const blockedWritePath =
      extractTrapBlockedPath(result.landstripErrorOutput, cwd, 'write') ??
      extractNativeWriteDeniedPath(`${result.stderr}\n${result.landstripErrorOutput}`, cwd);
    if (blockedWritePath) {
      const retryResult = await retryWithAccess('write', blockedWritePath);
      if (retryResult) return retryResult;
    }
    const blockedReadPath = blockedReadPathForRetry(
      `${result.stderr}\n${result.landstripErrorOutput}`,
      result.landstripErrorOutput,
    );
    if (blockedReadPath) {
      const retryResult = await retryWithAccess('read', blockedReadPath);
      if (retryResult) return retryResult;
    }
    const landstripErrors = parseLandstripTraps(result.landstripErrorOutput);
    if (landstripErrors.length > 0) {
      throw new Error(formatLandstripTraps(landstripErrors));
    }
    return result;
  }

  async function executeSandboxedOnce(
    ctx: ExtensionContext,
    request: SandboxExecRequest,
    allowances: ExecutionAllowances,
    promptOnBlock: boolean,
  ): Promise<SandboxExecResult> {
    const { command, cwd, onData, signal, timeout, env } = request;
    const config = loadConfig(cwd);
    const { token: proxyToken, authorization: proxyAuthorization } = createProxyCredentials();
    const proxy = shouldStartProxy(config)
      ? await startProxy(
          ctx,
          cwd,
          allowances,
          signal,
          proxyAuthorization,
          restrictedUserProxyPortRange(),
        )
      : null;

    let policy: { dir: string; path: string } | undefined;
    let invocation: LandstripShellInvocation | undefined;
    let processAllowances = allowances;
    let teardownPromise: Promise<void> | undefined;
    const teardownResources = (): Promise<void> => {
      teardownPromise ??= Promise.all([
        Promise.resolve().then(() => invocation?.dispose?.()),
        Promise.resolve().then(() => {
          if (policy) rmSync(policy.dir, { recursive: true, force: true });
        }),
        Promise.resolve().then(() => proxy?.stop()),
      ]).then(() => undefined);
      return teardownPromise;
    };

    let landstripArgs: string[];
    try {
      invocation = await shellProvider.prepare({
        command,
        cwd,
        env: shellEnvironment(env, cwd, proxy?.port ?? null, proxy ? proxyToken : undefined),
        signal,
      });
      if (!invocation.executable.trim()) {
        throw new Error(`Shell provider "${shellProvider.id}" returned an empty executable`);
      }
      if (signal?.aborted) throw new Error('aborted');
      processAllowances = {
        ...allowances,
        readPaths: [...allowances.readPaths, ...(invocation.readPaths ?? [])],
      };
      processAllowances = withWindowsProcessReadAccess(
        processAllowances,
        invocation.executable,
        cwd,
      );
      policy = writePolicyFile(cwd, proxy?.port ?? null, 'shell', processAllowances);
      landstripArgs = ['run', '-p', policy.path, '--', invocation.executable, ...invocation.args];
      if (process.platform !== 'win32') landstripArgs.splice(1, 0, '--trap', '3');
    } catch (error) {
      await teardownResources();
      throw error;
    }

    return new Promise((resolvePromise, reject) => {
      let pendingSocketPair: [NetSocket, NetSocket] | undefined;
      (async () => {
        let timeoutHandle: NodeJS.Timeout | undefined;
        let timedOut = false;
        let cleaned = false;
        let trapSocket: NetSocket | undefined;
        let childEnd: NetSocket | undefined;
        if (process.platform !== 'win32') {
          pendingSocketPair = await createSocketPair();
          [trapSocket, childEnd] = pendingSocketPair;
        }
        if (signal?.aborted) throw new Error('aborted');
        const cleanup = async () => {
          if (cleaned) return;
          cleaned = true;
          if (timeoutHandle) clearTimeout(timeoutHandle);
          signal?.removeEventListener('abort', onAbort);
          trapSocket?.destroy();
          await teardownResources();
        };

        const stdio: StdioOptions = childEnd
          ? ['ignore', 'pipe', 'pipe', childEnd]
          : ['ignore', 'pipe', 'pipe'];
        const child: ChildProcess = spawn(binaryPath(), landstripArgs, {
          cwd,
          env: createLandstripLauncherEnvironment(invocation!.launcherEnv),
          detached: true,
          stdio,
        });
        patchProcessGroupKill(child);
        // Child has dup'd its end; parent can close its copy.
        childEnd?.destroy();
        pendingSocketPair = undefined;

        function killChild(): void {
          child.kill('SIGKILL');
        }
        function onAbort(): void {
          killChild();
        }

        if (timeout !== undefined && timeout > 0) {
          timeoutHandle = setTimeout(() => {
            timedOut = true;
            killChild();
          }, timeout * 1000);
        }

        signal?.addEventListener('abort', onAbort, { once: true });
        if (signal?.aborted) onAbort();

        let stderrAcc = '';
        let stdoutAcc = '';
        let errorFdAcc = '';
        let execSettled = false;
        let childExited = false;
        let childExitCode: number | null = null;
        let postExitTimer: NodeJS.Timeout | undefined;
        let stdoutEnded = child.stdout === null;
        let stderrEnded = child.stderr === null;

        const finalizeExec = (code: number | null): void => {
          if (execSettled) return;
          execSettled = true;
          if (postExitTimer) clearTimeout(postExitTimer);
          // Stop tracking the inherited pipes: a backgrounded grandchild can
          // hold them open after the command itself exits, so 'close' would
          // otherwise never arrive.
          child.stdout?.destroy();
          child.stderr?.destroy();
          void (async () => {
            await cleanup();
            if (signal?.aborted) {
              resolvePromise({
                exitCode: code,
                stdout: stdoutAcc,
                stderr: stderrAcc,
                landstripErrorOutput: errorFdAcc,
                cancelled: true,
                timedOut: false,
              });
              return;
            }
            if (timedOut) {
              resolvePromise({
                exitCode: code,
                stdout: stdoutAcc,
                stderr: stderrAcc,
                landstripErrorOutput: errorFdAcc,
                cancelled: false,
                timedOut: true,
              });
              return;
            }
            // Structured traps are trusted only from the trap socket; on
            // Windows, where --trap is unsupported, use native kernel-denial
            // text from stderr.
            const blockedPath =
              extractTrapBlockedPath(errorFdAcc, cwd) ?? extractNativeDeniedPath(stderrAcc, cwd);
            if (!blockedPath && ctx.hasUI) {
              const traps = parseLandstripTraps(errorFdAcc);
              const denials = traps.filter(isDenialTrap);
              if (denials.length > 0) {
                notify(
                  ctx,
                  `Sandbox blocked an operation: ${formatLandstripTraps(denials)}`,
                  'warning',
                );
              }
              const failures = traps.filter((trap) => !isDenialTrap(trap));
              if (failures.length > 0) {
                notify(ctx, `Sandbox failed: ${formatLandstripTraps(failures)}`, 'error');
              }
            }
            resolvePromise({
              exitCode: code,
              stdout: stdoutAcc,
              stderr: stderrAcc,
              landstripErrorOutput: errorFdAcc,
              cancelled: false,
              timedOut: false,
            });
          })().catch(reject);
        };

        const maybeFinalizeAfterExit = (): void => {
          if (childExited && !execSettled && stdoutEnded && stderrEnded) {
            finalizeExec(childExitCode);
          }
        };

        child.stdout?.on('data', (data: Buffer) => {
          stdoutAcc += data.toString('utf8');
          onData(data);
        });
        child.stderr?.on('data', (data: Buffer) => {
          stderrAcc += data.toString('utf8');
          onData(data);
        });
        child.stdout?.once('end', () => {
          stdoutEnded = true;
          maybeFinalizeAfterExit();
        });
        child.stderr?.once('end', () => {
          stderrEnded = true;
          maybeFinalizeAfterExit();
        });

        const trapDecoder = new StringDecoder('utf8');
        let trapBuffer = '';
        let queryChain: Promise<void> = Promise.resolve();
        const respondQuery = (
          queryId: string,
          action: LandstripControlResponse['action'],
        ): void => {
          if (!trapSocket || trapSocket.destroyed) return;
          trapSocket.write(controlResponseLine(queryId, action));
        };
        // Surface a denial through the error-fd accumulator so the post-close
        // notify and the exec retry paths still work.
        const appendErrorLine = (line: string): void => {
          errorFdAcc += line + '\n';
        };
        trapSocket?.on('data', (data: Buffer) => {
          trapBuffer += trapDecoder.write(data);
          let nl = trapBuffer.indexOf('\n');
          while (nl !== -1) {
            const line = trapBuffer.slice(0, nl);
            trapBuffer = trapBuffer.slice(nl + 1);
            nl = trapBuffer.indexOf('\n');
            if (line.length === 0) continue;
            const trap = parseTrapLine(line);
            // An unanswered query holds the child's syscall, so every query
            // gets an answer; anything else is informational and kept for
            // post-close handling.
            if (trap && isQueryTrap(trap)) {
              queryChain = queryChain
                .then(async () => {
                  const result = await resolveTrapQuery(
                    trap,
                    ctx,
                    cwd,
                    processAllowances,
                    promptOnBlock,
                    signal,
                  );
                  if (
                    result.reason === 'unprompted' ||
                    (!isFilesystemTrap(trap) && result.reason === 'rejected')
                  ) {
                    appendErrorLine(line);
                  }
                  respondQuery(trap.query_id, result.action);
                })
                .catch(() => respondQuery(trap.query_id, 'deny'));
            } else {
              appendErrorLine(line);
            }
          }
        });

        child.on('error', (error) => {
          if (execSettled) return;
          execSettled = true;
          if (postExitTimer) clearTimeout(postExitTimer);
          void (async () => {
            try {
              await cleanup();
              reject(error);
            } catch (cleanupError) {
              reject(cleanupError);
            }
          })();
        });
        // Settle on 'exit' — the command itself has ended — rather than
        // waiting for 'close', which only fires once every inherited stdio
        // pipe is closed. A backgrounded process holding one open would
        // otherwise block us indefinitely.
        child.once('exit', (code) => {
          childExited = true;
          childExitCode = code;
          maybeFinalizeAfterExit();
          if (!execSettled) {
            postExitTimer = setTimeout(() => finalizeExec(code), EXIT_STDIO_GRACE_MS);
          }
        });
        child.once('close', (code) => finalizeExec(code));
      })().catch((error: unknown) => {
        // A failure before the child is wired (for example, creating the trap
        // channel) never reaches cleanup(), so free temporary resources here.
        pendingSocketPair?.forEach((socket) => socket.destroy());
        void teardownResources().then(
          () => reject(error),
          (cleanupError) =>
            reject(new AggregateError([error, cleanupError], 'Shell setup and cleanup failed')),
        );
      });
    });
  }

  function warnIfAllDomainsAllowed(ctx: ExtensionContext, config: SandboxConfig): void {
    if (config.network.allowNetwork) {
      notify(ctx, 'Network sandbox is disabled because network.allowNetwork is true.', 'warning');
      return;
    }
    if (!allowsAllDomains(config.network.allowedDomains)) return;
    notify(
      ctx,
      'Network sandbox allows all domains because network.allowedDomains contains "*".',
      'warning',
    );
  }

  function warnIfWindowsSecurityDowngraded(ctx: ExtensionContext, config: SandboxConfig): void {
    if (process.platform !== 'win32') return;
    let implementation: WindowsImplementation;
    try {
      implementation = windowsStatus().active;
    } catch (error) {
      notify(ctx, formatError(error), 'error');
      return;
    }
    if (implementation !== 'appContainer') return;
    if (config.windows.appContainerMode === 'standard') {
      notify(
        ctx,
        'Windows uses standard AppContainer mode, which is weaker than LPAC isolation.',
        'warning',
      );
    }
    if (config.windows.allowLoopback) {
      notify(
        ctx,
        'Windows loopback access includes all local loopback services, not only the Landstrip proxy.',
        'warning',
      );
    }
  }

  function enableStatus(ctx: ExtensionContext, config: SandboxConfig): void {
    if (!hasTuiStatus(ctx)) return;
    const theme = ctx.ui.theme;
    const dot = theme.fg('success', '●');
    const label = theme.fg('text', 'Sandbox');

    const windowsImplementation = process.platform === 'win32' ? windowsStatus().active : undefined;
    let networkLabel: string;
    let networkColor: 'warning' | 'accent';
    if (config.network.allowNetwork) {
      networkLabel = 'unrestricted';
      networkColor = 'warning';
    } else if (windowsImplementation === 'appContainer' && !config.windows.allowLoopback) {
      networkLabel = 'blocked';
      networkColor = 'accent';
    } else if (allowsAllDomains(config.network.allowedDomains)) {
      networkLabel = 'any domain';
      networkColor = 'warning';
    } else {
      networkLabel = `${config.network.allowedDomains.length} domains`;
      networkColor = 'accent';
    }

    const sep = theme.fg('dim', '·');
    const net = theme.fg(networkColor, networkLabel);
    const write = theme.fg('accent', `${config.filesystem.allowWrite.length} write paths`);
    const fields = [`${dot} ${label}`, net, write];
    if (windowsImplementation !== undefined) {
      const standard =
        windowsImplementation === 'appContainer' && config.windows.appContainerMode === 'standard';
      const implementationLabel =
        windowsImplementation === 'restrictedUser'
          ? 'restricted user'
          : `${config.windows.appContainerMode} AppContainer`;
      fields.splice(1, 0, theme.fg(standard ? 'warning' : 'accent', implementationLabel));
    }

    setTuiStatus(ctx, 'sandbox', fields.join(`  ${sep}  `));
  }

  const headlessWarnings = new Set<string>();

  // Explicitly disabling sandboxing permits the legacy unsandboxed fallback.
  // Initialization failures remain fail-closed so commands never bypass policy silently.
  function warnUnsandboxed(ctx: ExtensionContext, message: string, level: NotificationLevel): void {
    notify(ctx, message, level);
    if (!ctx.hasUI && !headlessWarnings.has(message)) {
      headlessWarnings.add(message);
      console.error(`omp-landstrip: ${message}`);
    }
  }

  function enableSandbox(ctx: ExtensionContext): boolean {
    const config = loadConfig(ctx.cwd);

    if (!SUPPORTED_PLATFORMS.has(process.platform)) {
      sandboxEnabled = false;
      sandboxReady = false;
      sandboxState = 'unavailable';
      warnUnsandboxed(
        ctx,
        `landstrip sandboxing is not supported on ${process.platform}`,
        'warning',
      );
      return false;
    }

    // Resolve through the plugin dependency. A missing platform package is a
    // broken installation and must abort enablement instead of selecting an
    // unsandboxed execution route.
    binaryPath();

    sandboxEnabled = true;
    sandboxReady = true;
    sandboxState = 'enabled';
    warnIfAllDomainsAllowed(ctx, config);
    warnIfWindowsSecurityDowngraded(ctx, config);
    enableStatus(ctx, config);
    return true;
  }

  let getNoSandboxFlag = (): boolean => false;
  function disableSandbox(ctx: ExtensionContext): void {
    sandboxEnabled = false;
    sandboxReady = false;
    sandboxState = 'disabled';
    setTuiStatus(ctx, 'sandbox', undefined);
  }

  function ensureSandboxState(ctx: ExtensionContext): boolean {
    const config = loadConfig(ctx.cwd);
    if (!config.enabled) {
      disableSandbox(ctx);
      return false;
    }

    if (!sandboxEnabled || !sandboxReady) return enableSandbox(ctx);
    return true;
  }

  const bashParameters = Type.Object({
    command: Type.String(),
    cwd: Type.Optional(Type.String()),
    timeout: Type.Optional(Type.Number()),
  });

  function createBashTool(): ToolDefinition<typeof bashParameters> {
    return {
      name: 'bash',
      label: 'bash (landstrip)',
      description: 'Execute commands with the Landstrip OS sandbox.',
      parameters: bashParameters,
      loadMode: 'essential',
      shellEnv: () => ({}),
      async execute(_toolCallId, params, signal, onUpdate, ctx: ExtensionContext) {
        if (sandboxState === 'unavailable') {
          throw new Error('Sandbox is unavailable; refusing command');
        }
        if (!ensureSandboxState(ctx)) {
          if (ctx.invokeTool) {
            return ctx.invokeTool(params as Record<string, unknown>, { signal, onUpdate });
          }
          throw new Error('Sandbox is disabled; native bash is unavailable');
        }
        const result = await executeSandboxed(
          ctx,
          {
            command: params.command,
            cwd: params.cwd ?? ctx.cwd,
            onData: (chunk) => {
              onUpdate?.({ content: [{ type: 'text', text: chunk.toString('utf8') }] });
            },
            signal,
            timeout: params.timeout,
            env: process.env,
          },
          true,
        );
        if (result.cancelled) throw new Error('aborted');
        if (result.timedOut) throw new Error(`timeout:${params.timeout}`);
        const traps = parseLandstripTraps(result.landstripErrorOutput);
        if (traps.length > 0) {
          throw new Error(formatLandstripTraps(traps));
        }
        return {
          content: [{ type: 'text', text: `${result.stdout}${result.stderr}` }],
          details: { exitCode: result.exitCode },
        };
      },
    };
  }

  function register(pi: ExtensionAPI): void {
    if (shouldRegisterBashTool) pi.registerTool(createBashTool());

    pi.on('user_bash', async (event, ctx) => {
      if (!ensureSandboxState(ctx)) {
        if (sandboxState === 'unavailable') {
          throw new Error('Sandbox is unavailable; refusing command');
        }
        return {};
      }
      const result = await executeSandboxed(
        ctx,
        {
          command: event.command,
          cwd: event.cwd,
          onData: () => undefined,
          env: process.env,
        },
        true,
      );
      const output = `${result.stdout}${result.stderr}`;
      return {
        result: {
          output,
          exitCode: result.exitCode ?? undefined,
          cancelled: result.cancelled,
          timedOut: result.timedOut,
          truncated: false,
          totalLines: 0,
          totalBytes: output.length,
          outputLines: 0,
          outputBytes: output.length,
          workingDir: event.cwd,
        },
      };
    });

    pi.on('session_start', async (_event, ctx) => {
      activeContext = ctx;
      permissionPrompts.reset();
      sessionAllowedDomains.length = 0;
      sessionAllowedReadPaths.length = 0;
      sessionAllowedWritePaths.length = 0;
      sessionAllowedTargets.length = 0;
      projectConfigTrusted = ctx.isProjectTrusted();
      const config = loadConfig(ctx.cwd);
      if (!config.enabled) {
        disableSandbox(ctx);
        notify(ctx, 'Sandbox disabled via config', 'info');
        return;
      }
      if (enableSandbox(ctx)) {
        ctx.ui.setStatus?.('sandbox', 'landstrip');
      }
    });
    pi.on('session_shutdown', () => {
      permissionPrompts.reset();
      activeContext = undefined;
    });
  }

  async function applySandboxSetting(
    ctx: ExtensionContext,
    enabled: boolean | undefined,
    scope: SandboxConfigScope,
  ): Promise<void> {
    await writeSandboxConfigEnabled(ctx.cwd, enabled, scope);
    const effectiveEnabled = loadConfig(ctx.cwd).enabled;
    if (!effectiveEnabled) {
      disableSandbox(ctx);
    } else if (!getNoSandboxFlag()) {
      enableSandbox(ctx);
    }
  }

  function sandboxOverview(cwd: string, includeProject: boolean): SandboxOverview {
    const config = loadSandboxConfig(cwd, includeProject);
    const { globalPath, projectPath } = getOmpConfigPaths(cwd, 'sandbox.json');
    const windowsImplementation = process.platform === 'win32' ? windowsStatus().active : undefined;
    return {
      enabled: config.enabled,
      running: sandboxEnabled && sandboxReady,
      noSandboxFlag: getNoSandboxFlag(),
      networkMode: config.network.allowNetwork
        ? 'unrestricted'
        : windowsImplementation === 'appContainer' && !config.windows.allowLoopback
          ? 'blocked'
          : 'proxied',
      shellReadMode: process.platform === 'win32' ? 'policy' : config.shell.readAccess,
      readRuleScope: enforcesShellReadPolicy(config.shell.readAccess)
        ? 'Workers and shell'
        : 'Workers only',
      windowsMode:
        windowsImplementation === undefined
          ? undefined
          : windowsImplementation === 'restrictedUser'
            ? 'Restricted user'
            : `AppContainer (${config.windows.appContainerMode})`,
      changeScope: getSandboxConfigWriteTarget(cwd, includeProject).scope,
      paths: { global: globalPath, project: projectPath, binary: binaryPath() },
      config,
      sessionDomains: [...sessionAllowedDomains],
      sessionReadPaths: [...sessionAllowedReadPaths],
      sessionWritePaths: [...sessionAllowedWritePaths],
    };
  }

  const sandboxCallbacks: SandboxCallbacks = {
    load: loadSandboxEnabledSettings,
    setEnabled: (ctx, enabled, scope) => applySandboxSetting(ctx, enabled, scope),
    clearProject: (ctx) => applySandboxSetting(ctx, undefined, 'project'),
    overview: sandboxOverview,
  };

  const integration: LandstripIntegration = {
    getExtensionContext: () => activeContext,
    register,
    sandboxCallbacks,
  };
  return integration;
}
