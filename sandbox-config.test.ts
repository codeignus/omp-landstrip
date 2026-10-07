import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';
import {
  deepMergeSandboxConfig,
  parseSandboxConfig,
  type SandboxConfig,
  type SandboxConfigFile,
} from '@landstrip/landstrip-api/shared';

describe('sandbox config in pi-landstrip', () => {
  it('parses bundled sandbox.json correctly', () => {
    const raw = JSON.parse(
      readFileSync(new URL('./sandbox.json', import.meta.url), 'utf8'),
    ) as unknown;
    const parsed = parseSandboxConfig(raw);

    expect(parsed.enabled).toBe(true);
    expect(parsed.shell?.readAccess).toBe('host');
    expect(parsed.network?.allowNetwork).toBe(false);
    expect(parsed.filesystem?.allowRead).toContain('.');
    expect(parsed.filesystem?.denyWrite).toContain('**/.env');
    expect(parsed.windows?.appContainerMode).toBe('standard');
  });

  it('deep merges configuration overrides', () => {
    const base: SandboxConfig = {
      enabled: true,
      shell: { readAccess: 'host' },
      network: {
        allowNetwork: false,
        allowLocalBinding: false,
        allowAllUnixSockets: false,
        allowUnixSockets: ['/tmp/sock1'],
        allowedDomains: ['example.com'],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: ['/Users'],
        denyReadAlways: [],
        allowRead: ['.'],
        allowWrite: ['.'],
        denyWrite: ['**/.env'],
        denyWriteAlways: [],
      },
      windows: {
        appContainerMode: 'standard',
        allowLoopback: false,
      },
    };

    const overrides: SandboxConfigFile = {
      network: {
        allowedDomains: ['api.example.com'],
      },
      filesystem: {
        denyWriteAlways: ['/etc/passwd'],
      },
      shell: {
        readAccess: 'policy',
      },
    };

    const merged = deepMergeSandboxConfig(base, overrides);
    expect(merged.enabled).toBe(true);
    expect(merged.shell?.readAccess).toBe('policy');
    expect(merged.network.allowedDomains).toEqual(['example.com', 'api.example.com']);
    expect(merged.filesystem.denyWriteAlways).toEqual(['/etc/passwd']);
  });
});
