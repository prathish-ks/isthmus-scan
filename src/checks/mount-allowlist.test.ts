import fs from 'fs';
import path from 'path';
import os from 'os';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { checkMountAllowlist } from './mount-allowlist.js';

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'isthmus-scan-test-'));
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function write(name: string, content: unknown): string {
  const p = path.join(dir, name);
  fs.writeFileSync(p, JSON.stringify(content));
  return p;
}

describe('checkMountAllowlist', () => {
  it('warns when no allowlist file exists', () => {
    const result = checkMountAllowlist(path.join(dir, 'missing.json'));
    expect(result.level).toBe('warn');
    // NanoClaw vets this file itself; the kernel only takes over once it is enforcing.
    expect(result.enforcement).toBe('nanoclaw-native');
    expect(checkMountAllowlist(path.join(dir, 'missing.json'), true).enforcement).toBe('isthmus-kernel');
  });

  it('fails to parse invalid JSON', () => {
    const p = path.join(dir, 'bad.json');
    fs.writeFileSync(p, '{not json');
    const result = checkMountAllowlist(p);
    expect(result.level).toBe('fail');
  });

  it('passes an empty allowlist', () => {
    const p = write('empty.json', { allowedRoots: [], blockedPatterns: [] });
    const result = checkMountAllowlist(p);
    expect(result.level).toBe('pass');
  });

  it('passes a narrowly-scoped allowlist', () => {
    const p = write('scoped.json', { allowedRoots: [{ path: '/Users/me/project/group-1' }] });
    expect(checkMountAllowlist(p).level).toBe('pass');
  });

  it.each(['/', '/etc', '/root', '/home', '/var', '/usr', '/bin', '/sbin', '/boot'])(
    'flags dangerous root %s',
    (root) => {
      const p = write('dangerous.json', { allowedRoots: [{ path: root }] });
      const result = checkMountAllowlist(p);
      expect(result.level).toBe('fail');
      expect(result.detail).toContain(root);
    },
  );

  it('does not false-positive on a path that merely starts with a dangerous root name', () => {
    // /etcetera is not /etc — must not match via naive prefix comparison.
    const p = write('lookalike.json', { allowedRoots: [{ path: '/etcetera/project' }] });
    expect(checkMountAllowlist(p).level).toBe('pass');
  });

  it.each(['/var/run/docker.sock', '/run/docker.sock', '/var/run/podman.sock'])(
    'flags an exact docker/podman socket path %s',
    (sock) => {
      const p = write('sock.json', { allowedRoots: [{ path: sock }] });
      const result = checkMountAllowlist(p);
      expect(result.level).toBe('fail');
      expect(result.detail).toContain('Docker/Podman socket');
    },
  );

  it('flags a root that covers a docker socket without being the exact path', () => {
    const p = write('covers.json', { allowedRoots: [{ path: '/var/run' }] });
    const result = checkMountAllowlist(p);
    expect(result.level).toBe('fail');
    expect(result.detail).toContain('Docker/Podman socket');
  });

  it('tolerates a trailing slash on an allowed root', () => {
    const p = write('trailing.json', { allowedRoots: [{ path: '/etc/' }] });
    expect(checkMountAllowlist(p).level).toBe('fail');
  });
});
