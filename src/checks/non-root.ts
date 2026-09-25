/**
 * Confirms the agent container image runs as a non-root user. This is
 * NanoClaw's own default (container/Dockerfile's `USER node`), not
 * something Isthmus adds — this check exists to catch a local override,
 * not to claim credit for the default.
 */
import fs from 'fs';
import path from 'path';

import type { CheckResult } from '../report.js';

export function findDockerfile(target: string): string | null {
  const candidates = [path.join(target, 'container', 'Dockerfile'), path.join(target, 'Dockerfile')];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

export function checkNonRoot(target: string): CheckResult {
  const name = 'non-root containers';
  const dockerfilePath = findDockerfile(target);

  if (!dockerfilePath) {
    return {
      name,
      level: 'skip',
      detail: `no Dockerfile found under ${target} — is this a NanoClaw checkout?`,
      enforcement: 'unenforced',
    };
  }

  const lines = fs.readFileSync(dockerfilePath, 'utf8').split('\n');
  let lastUser: string | null = null;
  for (const rawLine of lines) {
    const line = rawLine.trim();
    const match = line.match(/^USER\s+(\S+)/i);
    if (match) lastUser = match[1];
  }

  if (lastUser === null) {
    return {
      name,
      level: 'fail',
      detail: `${dockerfilePath} has no USER directive — Docker defaults to root when none is set`,
      remediation: 'add a non-root USER directive before the image is built',
      enforcement: 'unenforced',
    };
  }

  if (lastUser === 'root' || lastUser === '0') {
    return {
      name,
      level: 'fail',
      detail: `${dockerfilePath}'s last USER directive is '${lastUser}' — agent containers run as root`,
      remediation: 'switch back to a non-root user (NanoClaw ships this as USER node by default)',
      enforcement: 'unenforced',
    };
  }

  return {
    name,
    level: 'pass',
    detail: `${dockerfilePath} runs as '${lastUser}', not root`,
    enforcement: 'nanoclaw-native',
  };
}
