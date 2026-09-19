/**
 * Audits NanoClaw's mount-allowlist.json for suspiciously broad roots and
 * Docker/Podman socket coverage. Mirrors Isthmus's own Go implementation
 * (go-host/internal/securitycheck/securitycheck.go's checkDangerousMounts) —
 * same dangerous-roots list, same socket paths, same reasoning: this is a
 * human-facing sanity pass over the config file an operator hand-edits, not
 * a claim about NanoClaw's own runtime enforcement (which is a separate,
 * real gap — see https://github.com/nanocoai/nanoclaw/pull/3680).
 */
import fs from 'fs';
import os from 'os';
import path from 'path';

import type { CheckResult } from '../report.js';

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

export function checkMountAllowlist(allowlistPath: string = defaultAllowlistPath()): CheckResult {
  const name = 'mount-allowlist exposure';

  if (!fs.existsSync(allowlistPath)) {
    return {
      name,
      level: 'warn',
      detail: `no mount-allowlist configured at ${allowlistPath} — on a NanoClaw install without the mount-allowlist-validatespec-gap fix (nanocoai/nanoclaw#3680), this means every allowlisted-extra mount (e.g. a Docker-socket or credential-directory bind) is trusted with no independent check at all`,
      remediation: 'configure one via the manage-mounts skill, or ncl groups config, then re-run this scan',
      isthmusEnforced: true,
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
      isthmusEnforced: true,
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
      isthmusEnforced: true,
    };
  }

  return {
    name,
    level: 'pass',
    detail: `mount-allowlist at ${allowlistPath} has ${(parsed.allowedRoots ?? []).length} root(s), none suspiciously broad or socket-covering`,
    isthmusEnforced: true,
  };
}
