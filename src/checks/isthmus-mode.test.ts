import { createHash } from 'crypto';
import fs from 'fs';
import net from 'net';
import path from 'path';
import os from 'os';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { detectIsthmus, checkKernelLiveness, kernelSocketCandidates } from './isthmus-mode.js';

let dir: string;
let runtimeDir: string;
const originalSocketEnv = process.env.NANOCLAW_KERNEL_SOCKET;
const originalXdg = process.env.XDG_RUNTIME_DIR;

/** The path the host would actually bind for a checkout at `root`. */
function expectedRuntimeSocket(base: string, root: string): string {
  const slug = createHash('sha1').update(root).digest('hex').slice(0, 8);
  return path.join(base, `nanoclaw-${slug}`, 'nanogo-kernel.sock');
}

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'isthmus-scan-mode-test-'));
  // Short base on purpose: a Unix socket path caps at 104 bytes on
  // macOS/BSD, which is the whole reason the real socket moved here.
  runtimeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'isr-'));
  delete process.env.NANOCLAW_KERNEL_SOCKET;
  process.env.XDG_RUNTIME_DIR = runtimeDir;
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(runtimeDir, { recursive: true, force: true });
  if (originalSocketEnv === undefined) delete process.env.NANOCLAW_KERNEL_SOCKET;
  else process.env.NANOCLAW_KERNEL_SOCKET = originalSocketEnv;
  if (originalXdg === undefined) delete process.env.XDG_RUNTIME_DIR;
  else process.env.XDG_RUNTIME_DIR = originalXdg;
});

/** Binds a real listening Unix socket at `socketPath`, creating its parent. */
async function listenAt(socketPath: string): Promise<net.Server> {
  fs.mkdirSync(path.dirname(socketPath), { recursive: true });
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  return server;
}

describe('detectIsthmus', () => {
  it('is false for a plain directory', () => {
    expect(detectIsthmus(dir)).toBe(false);
  });

  it('is true when go-host/ exists', () => {
    fs.mkdirSync(path.join(dir, 'go-host'));
    expect(detectIsthmus(dir)).toBe(true);
  });
});

describe('kernelSocketCandidates', () => {
  it('derives the runtime-dir path from sha1(projectRoot)[:8], matching the host', () => {
    const candidates = kernelSocketCandidates(dir);
    const real = fs.realpathSync(dir);
    // Both spellings are probed when they differ (macOS's /var -> /private/var
    // makes this the normal case, not the exotic one).
    expect(candidates.map((c) => c.path)).toContain(expectedRuntimeSocket(runtimeDir, real));
    expect(candidates.some((c) => c.origin === 'runtime-dir')).toBe(true);
  });

  it('falls back to XDG_RUNTIME_DIR being unset', () => {
    delete process.env.XDG_RUNTIME_DIR;
    const candidates = kernelSocketCandidates(dir);
    expect(candidates.map((c) => c.path)).toContain(expectedRuntimeSocket(os.tmpdir(), fs.realpathSync(dir)));
  });

  it('still probes the legacy data/ path last', () => {
    const candidates = kernelSocketCandidates(dir);
    expect(candidates[candidates.length - 1]).toEqual({
      path: path.join(dir, 'data', 'nanogo-kernel.sock'),
      origin: 'legacy-data-dir',
    });
  });

  it('treats an env override as exclusive — never falls back past it', () => {
    process.env.NANOCLAW_KERNEL_SOCKET = '/tmp/explicit.sock';
    expect(kernelSocketCandidates(dir)).toEqual([{ path: '/tmp/explicit.sock', origin: 'env' }]);
  });

  it('reads a .env override, which the host honors but never puts in process.env', () => {
    fs.writeFileSync(path.join(dir, '.env'), '# a comment\nNANOCLAW_KERNEL_SOCKET="/tmp/from-dotenv.sock"\n');
    expect(kernelSocketCandidates(dir)).toEqual([{ path: '/tmp/from-dotenv.sock', origin: 'dotenv' }]);
  });

  it('ignores an empty .env value, matching readEnvFile', () => {
    fs.writeFileSync(path.join(dir, '.env'), 'NANOCLAW_KERNEL_SOCKET=\n');
    expect(kernelSocketCandidates(dir).some((c) => c.origin === 'dotenv')).toBe(false);
  });

  it('prefers a real env var over a .env value', () => {
    fs.writeFileSync(path.join(dir, '.env'), 'NANOCLAW_KERNEL_SOCKET=/tmp/from-dotenv.sock\n');
    process.env.NANOCLAW_KERNEL_SOCKET = '/tmp/from-env.sock';
    expect(kernelSocketCandidates(dir)).toEqual([{ path: '/tmp/from-env.sock', origin: 'env' }]);
  });

  it('deduplicates when the target is already fully resolved', () => {
    const candidates = kernelSocketCandidates(dir);
    expect(new Set(candidates.map((c) => c.path)).size).toBe(candidates.length);
  });
});

describe('checkKernelLiveness', () => {
  it('passes on a healthy install, where the socket is in the runtime dir', async () => {
    const socketPath = expectedRuntimeSocket(runtimeDir, fs.realpathSync(dir));
    const server = await listenAt(socketPath);
    try {
      const result = await checkKernelLiveness(dir);
      expect(result.level).toBe('pass');
      expect(result.detail).toContain(socketPath);
    } finally {
      server.close();
    }
  });

  it('warns when the socket file does not exist at all', async () => {
    const result = await checkKernelLiveness(dir);
    expect(result.level).toBe('warn');
  });

  it('names every path it probed, so the warning is actionable', async () => {
    const result = await checkKernelLiveness(dir);
    expect(result.detail).toContain('Probed:');
    for (const candidate of kernelSocketCandidates(dir)) {
      expect(result.detail).toContain(candidate.path);
    }
  });

  it('warns when the socket path exists but nothing is listening (a stale file)', async () => {
    const socketPath = expectedRuntimeSocket(runtimeDir, fs.realpathSync(dir));
    fs.mkdirSync(path.dirname(socketPath), { recursive: true });
    // A plain file at the socket path, not an actual listening socket.
    fs.writeFileSync(socketPath, '');
    const result = await checkKernelLiveness(dir);
    expect(result.level).toBe('warn');
  });

  it('still passes on a pre-relocation install that binds under data/, and says so', async () => {
    const server = await listenAt(path.join(dir, 'data', 'nanogo-kernel.sock'));
    try {
      const result = await checkKernelLiveness(dir);
      expect(result.level).toBe('pass');
      expect(result.detail).toContain('pre-relocation');
    } finally {
      server.close();
    }
  });

  it('honors a NANOCLAW_KERNEL_SOCKET override', async () => {
    const socketPath = path.join(dir, 'custom.sock');
    process.env.NANOCLAW_KERNEL_SOCKET = socketPath;
    const server = await listenAt(socketPath);
    try {
      const result = await checkKernelLiveness(dir);
      expect(result.level).toBe('pass');
      expect(result.detail).toContain(socketPath);
    } finally {
      server.close();
    }
  });

  it('does not silently fall back to a live legacy socket when an override is set but stale', async () => {
    // The host would bind only the override, so reporting the legacy socket
    // as healthy would claim enforcement at a path nothing is using.
    const server = await listenAt(path.join(dir, 'data', 'nanogo-kernel.sock'));
    process.env.NANOCLAW_KERNEL_SOCKET = path.join(dir, 'stale.sock');
    try {
      const result = await checkKernelLiveness(dir);
      expect(result.level).toBe('warn');
    } finally {
      server.close();
    }
  });
});
