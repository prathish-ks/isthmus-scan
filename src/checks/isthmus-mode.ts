/**
 * Detects whether the target is an Isthmus checkout (has go-host/), and if
 * so, whether the kernel actually looks alive right now — a config file or
 * a built binary existing is not the same as the kernel being wired into
 * the running host, which is the thing that actually matters.
 */
import fs from 'fs';
import net from 'net';
import path from 'path';

import type { CheckResult } from '../report.js';

export function detectIsthmus(target: string): boolean {
  return fs.existsSync(path.join(target, 'go-host'));
}

function defaultKernelSocketPath(target: string): string {
  return path.join(target, 'data', 'nanogo-kernel.sock');
}

/** Connects to the kernel's Unix socket with a short timeout — presence of the file alone doesn't mean anything is listening. */
function probeSocket(socketPath: string, timeoutMs = 1000): Promise<boolean> {
  return new Promise((resolve) => {
    if (!fs.existsSync(socketPath)) {
      resolve(false);
      return;
    }
    const socket = net.createConnection(socketPath);
    const timer = setTimeout(() => {
      socket.destroy();
      resolve(false);
    }, timeoutMs);
    socket.once('connect', () => {
      clearTimeout(timer);
      socket.destroy();
      resolve(true);
    });
    socket.once('error', () => {
      clearTimeout(timer);
      resolve(false);
    });
  });
}

export async function checkKernelLiveness(target: string): Promise<CheckResult> {
  const name = 'Isthmus kernel liveness';
  const socketPath = process.env.NANOCLAW_KERNEL_SOCKET ?? defaultKernelSocketPath(target);
  const alive = await probeSocket(socketPath);

  if (alive) {
    return {
      name,
      level: 'pass',
      detail: `kernel socket at ${socketPath} is reachable — the mount-allowlist and egress checks above are being actively enforced, not just configured`,
      isthmusEnforced: true,
    };
  }

  return {
    name,
    level: 'warn',
    detail: `kernel socket at ${socketPath} is not reachable — this looks like an Isthmus checkout, but the kernel doesn't appear to be running, so nothing above is actually being enforced right now`,
    remediation: 'start NanoClaw normally, or run `nanogo doctor` for a full diagnostic',
    isthmusEnforced: true,
  };
}
