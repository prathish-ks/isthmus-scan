/**
 * Detects whether the target is an Isthmus checkout (has go-host/), and if
 * so, whether the kernel actually looks alive right now — a config file or
 * a built binary existing is not the same as the kernel being wired into
 * the running host, which is the thing that actually matters.
 */
import { createHash } from 'crypto';
import fs from 'fs';
import net from 'net';
import os from 'os';
import path from 'path';

import type { CheckResult } from '../report.js';

export function detectIsthmus(target: string): boolean {
  return fs.existsSync(path.join(target, 'go-host'));
}

/** Where a candidate socket path came from, so the report can say which one answered. */
export type SocketOrigin = 'env' | 'dotenv' | 'runtime-dir' | 'legacy-data-dir';

export interface SocketCandidate {
  path: string;
  origin: SocketOrigin;
}

/**
 * Mirrors src/install-slug.ts's getInstallSlug: sha1 of the project root,
 * hex, first 8 chars. The socket directory is named after this, so the hash
 * input has to match the host's byte for byte or the path we probe is a
 * path nothing ever bound.
 */
function installSlug(projectRoot: string): string {
  return createHash('sha1').update(projectRoot).digest('hex').slice(0, 8);
}

/**
 * Mirrors src/install-slug.ts's getRuntimeSocketDir. XDG_RUNTIME_DIR first
 * (Linux: user-scoped, mode 0700, tmpfs), falling back to os.tmpdir()
 * (macOS: Apple's per-user confined temp dir; Linux without a systemd user
 * session: /tmp).
 */
function runtimeSocketDir(projectRoot: string): string {
  const base = process.env.XDG_RUNTIME_DIR || os.tmpdir();
  return path.join(base, `nanoclaw-${installSlug(projectRoot)}`);
}

/**
 * Reads one key out of `<target>/.env` the way src/env.ts's readEnvFile
 * does — and for the same reason it matters here: readEnvFile deliberately
 * never copies values into process.env, so a NANOCLAW_KERNEL_SOCKET set
 * only in .env is invisible to anything that just checks the environment.
 * The host honors it; so must this.
 */
function readDotEnvValue(target: string, key: string): string | undefined {
  let content: string;
  try {
    content = fs.readFileSync(path.join(target, '.env'), 'utf8');
  } catch {
    return undefined;
  }
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    if (trimmed.slice(0, eqIdx).trim() !== key) continue;
    let value = trimmed.slice(eqIdx + 1).trim();
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")))
    ) {
      value = value.slice(1, -1);
    }
    // readEnvFile treats an empty value as absent; match that.
    return value || undefined;
  }
  return undefined;
}

/**
 * Every path the kernel socket could legitimately be at, in the host's own
 * precedence order (src/config.ts's KERNEL_SOCKET_PATH):
 *
 *   1. process.env.NANOCLAW_KERNEL_SOCKET
 *   2. `<target>/.env`'s NANOCLAW_KERNEL_SOCKET
 *   3. getRuntimeSocketDir(PROJECT_ROOT)/nanogo-kernel.sock
 *
 * An explicit override (1 or 2) is exclusive — the host binds exactly that
 * path and nothing else, so falling back past it would let this check
 * report a healthy kernel at a path the host isn't using.
 *
 * For case 3 the host's PROJECT_ROOT is a bare `process.cwd()`, which the
 * OS returns fully symlink-resolved. A path handed to this tool on the
 * command line is not, so a checkout reached through a symlink hashes to a
 * different slug. Both spellings are probed rather than guessing which one
 * the host was started with.
 *
 * The legacy `<target>/data/nanogo-kernel.sock` is probed last: that was
 * the layout before the socket moved off DATA_DIR (a Unix socket path caps
 * at 104 bytes on macOS/BSD, and a checkout can live arbitrarily deep), so
 * an install that predates the move still binds there.
 */
export function kernelSocketCandidates(target: string): SocketCandidate[] {
  const fromEnv = process.env.NANOCLAW_KERNEL_SOCKET;
  if (fromEnv) return [{ path: fromEnv, origin: 'env' }];

  const fromDotEnv = readDotEnvValue(target, 'NANOCLAW_KERNEL_SOCKET');
  if (fromDotEnv) return [{ path: fromDotEnv, origin: 'dotenv' }];

  const roots = [target];
  try {
    const real = fs.realpathSync(target);
    if (real !== target) roots.push(real);
  } catch {
    // Target doesn't resolve (deleted mid-scan, or a broken symlink).
    // Nothing to add — the unresolved spelling is still worth probing.
  }

  const candidates: SocketCandidate[] = roots.map((root) => ({
    path: path.join(runtimeSocketDir(root), 'nanogo-kernel.sock'),
    origin: 'runtime-dir' as const,
  }));
  candidates.push({ path: path.join(target, 'data', 'nanogo-kernel.sock'), origin: 'legacy-data-dir' });

  return candidates.filter((c, i) => candidates.findIndex((o) => o.path === c.path) === i);
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
  const candidates = kernelSocketCandidates(target);

  for (const candidate of candidates) {
    if (!(await probeSocket(candidate.path))) continue;

    const legacyNote =
      candidate.origin === 'legacy-data-dir'
        ? ' (at the pre-relocation data/ path — this install predates the move to a runtime directory, which is fine, but a deep checkout path can exceed the 104-byte socket limit on macOS)'
        : '';
    return {
      name,
      level: 'pass',
      detail: `kernel socket at ${candidate.path} is reachable${legacyNote} — the mount-allowlist and egress checks above are being actively enforced, not just configured`,
      isthmusEnforced: true,
    };
  }

  // Name every path probed. The operator can only act on this if they know
  // where it was looked for — and an override set in .env but pointing
  // somewhere stale is otherwise indistinguishable from a kernel that
  // simply isn't running.
  const probed = candidates.map((c) => `${c.path} [${c.origin}]`).join('\n    ');
  return {
    name,
    level: 'warn',
    detail: `no kernel socket answered — this looks like an Isthmus checkout, but the kernel doesn't appear to be running, so nothing above is actually being enforced right now. Probed:\n    ${probed}`,
    remediation:
      'start NanoClaw normally (the host spawns `nanogo serve` as a supervised child), or run `nanogo doctor` for a full diagnostic',
    isthmusEnforced: true,
  };
}
