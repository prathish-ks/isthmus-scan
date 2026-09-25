/**
 * Audits NanoClaw's mount-allowlist.json for suspiciously broad roots and
 * Docker/Podman socket coverage. Mirrors Isthmus's own Go implementation
 * (go-host/internal/securitycheck/securitycheck.go's checkDangerousMounts) —
 * same dangerous-roots list, same socket paths, same reasoning: this is a
 * human-facing sanity pass over the config file an operator hand-edits.
 *
 * Why that pass is load-bearing rather than belt-and-braces, verified against
 * upstream NanoClaw v2.4.0: `mountAllowed` (src/drivers/types.ts) returns
 * `true` UNCONDITIONALLY for the `allowlisted-extra` class — "Vetted upstream
 * by the mount-allowlist feature" — so the spec validator re-checks nothing.
 * The single vetting point is `validateAdditionalMounts`, called once at
 * src/container-runner.ts:1180. This file, and whatever that one call reads,
 * is all that stands between an operator-configured extra mount and the agent
 * container. See also https://github.com/nanocoai/nanoclaw/pull/3680.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';

import type { CheckResult, Enforcement } from '../report.js';

// Verbatim from go-host/internal/securitycheck/securitycheck.go.
const DANGEROUS_ROOTS = ['/', '/etc', '/root', '/home', '/var', '/usr', '/bin', '/sbin', '/boot'];
const DOCKER_SOCKET_PATHS = ['/var/run/docker.sock', '/run/docker.sock', '/var/run/podman.sock'];

interface AllowlistEntry {
  path: string;
  allowReadWrite?: boolean;
}

interface AllowlistFile {
  allowedRoots?: AllowlistEntry[];
  blockedPatterns?: string[];
}

export function defaultAllowlistPath(): string {
  return path.join(os.homedir(), '.config', 'nanoclaw', 'mount-allowlist.json');
}

export function checkMountAllowlist(
  allowlistPath: string = defaultAllowlistPath(),
  kernelEnforcing = false,
): CheckResult {
  const name = 'mount-allowlist exposure';
  // NanoClaw vets this file once, at composition time. Isthmus's kernel
  // re-validates it independently on every request, which is a different and
  // stronger claim — so which one is true right now depends on the scan.
  const enforcement: Enforcement = kernelEnforcing ? 'isthmus-kernel' : 'nanoclaw-native';

  if (!fs.existsSync(allowlistPath)) {
    return {
      name,
      level: 'warn',
      detail: `no mount-allowlist configured at ${allowlistPath} — and this file is the only gate. Upstream NanoClaw's spec validator permits the allowlisted-extra mount class unconditionally, so with no allowlist here, every allowlisted-extra mount (a Docker-socket or credential-directory bind among them) is trusted with no independent check at all`,
      remediation: 'configure one via the manage-mounts skill, or ncl groups config, then re-run this scan',
      enforcement,
    };
  }

  let parsed: AllowlistFile;
  try {
    parsed = JSON.parse(fs.readFileSync(allowlistPath, 'utf8'));
  } catch (err) {
    return {
      name,
      level: 'fail',
      detail: `could not parse ${allowlistPath} as JSON: ${err instanceof Error ? err.message : String(err)}`,
      remediation: 'fix the file\'s JSON syntax, or reset it via the manage-mounts skill',
      enforcement,
    };
  }

  const flagged: string[] = [];
  for (const root of parsed.allowedRoots ?? []) {
    const p = root.path.replace(/\/+$/, '') || '/';
    if (DANGEROUS_ROOTS.includes(p)) {
      flagged.push(`${root.path} — a whole system directory, not a project- or group-scoped path`);
    }
    for (const sock of DOCKER_SOCKET_PATHS) {
      if (p === sock || sock.startsWith(p + '/')) {
        flagged.push(`${root.path} — covers a Docker/Podman socket path`);
      }
    }
  }

  if (flagged.length > 0) {
    return {
      name,
      level: 'fail',
      detail: `mount-allowlist contains suspiciously broad or socket-covering root(s):\n    ${flagged.join('\n    ')}`,
      remediation:
        'narrow these entries to the specific project/group directories they should cover — a compromised agent that can reach the Docker socket can control every container on the machine, not just its own',
      enforcement,
    };
  }

  return {
    name,
    level: 'pass',
    detail: `mount-allowlist at ${allowlistPath} has ${(parsed.allowedRoots ?? []).length} root(s), none suspiciously broad or socket-covering`,
    enforcement,
  };
}
