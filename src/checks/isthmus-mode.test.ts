import fs from 'fs';
import net from 'net';
import path from 'path';
import os from 'os';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { detectIsthmus, checkKernelLiveness } from './isthmus-mode.js';

let dir: string;
const originalEnv = process.env.NANOCLAW_KERNEL_SOCKET;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'isthmus-scan-mode-test-'));
  delete process.env.NANOCLAW_KERNEL_SOCKET;
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
  if (originalEnv === undefined) delete process.env.NANOCLAW_KERNEL_SOCKET;
  else process.env.NANOCLAW_KERNEL_SOCKET = originalEnv;
});

describe('detectIsthmus', () => {
  it('is false for a plain directory', () => {
    expect(detectIsthmus(dir)).toBe(false);
  });

  it('is true when go-host/ exists', () => {
    fs.mkdirSync(path.join(dir, 'go-host'));
    expect(detectIsthmus(dir)).toBe(true);
  });
});

describe('checkKernelLiveness', () => {
  it('warns when the socket file does not exist at all', async () => {
    const result = await checkKernelLiveness(dir);
    expect(result.level).toBe('warn');
    expect(result.detail).toContain('not reachable');
  });

  it('warns when the socket path exists but nothing is listening (a stale file)', async () => {
    fs.mkdirSync(path.join(dir, 'data'), { recursive: true });
    // A plain file at the socket path, not an actual listening socket.
    fs.writeFileSync(path.join(dir, 'data', 'nanogo-kernel.sock'), '');
    const result = await checkKernelLiveness(dir);
    expect(result.level).toBe('warn');
  });

  it('passes when something is actually listening on the socket', async () => {
    fs.mkdirSync(path.join(dir, 'data'), { recursive: true });
    const socketPath = path.join(dir, 'data', 'nanogo-kernel.sock');
    const server = net.createServer();
    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
    try {
      const result = await checkKernelLiveness(dir);
      expect(result.level).toBe('pass');
      expect(result.detail).toContain('reachable');
    } finally {
      server.close();
    }
  });

  it('honors a NANOCLAW_KERNEL_SOCKET override', async () => {
    const socketPath = path.join(dir, 'custom.sock');
    process.env.NANOCLAW_KERNEL_SOCKET = socketPath;
    const server = net.createServer();
    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
    try {
      const result = await checkKernelLiveness(dir);
      expect(result.level).toBe('pass');
      expect(result.detail).toContain(socketPath);
    } finally {
      server.close();
    }
  });
});
