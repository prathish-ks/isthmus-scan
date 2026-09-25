/**
 * Checks how the agent container image is pinned in versions.json.
 *
 * Upstream NanoClaw pins it by digest
 * (`...nanoclaw/agent@sha256:79ac5063...`), and upstream's own
 * verify-agent-image.yml calls that file "the one file that decides what
 * other people's machines execute". A tag can be repointed at different
 * bytes at any time with nothing in the checkout changing; a digest cannot.
 * Isthmus applies the same discipline to its egress helper image, pinned by
 * digest with a CI drift watch.
 *
 * Static only, deliberately: comparing the pin against the image actually
 * present locally needs `docker image inspect`, which lands in the next
 * release together with the rest of the Docker read surface.
 */
import fs from 'fs';
import path from 'path';

import type { CheckResult } from '../report.js';

const DIGEST_PIN = /@sha256:[0-9a-f]{64}$/;

export function checkAgentImagePin(target: string): CheckResult {
  const name = 'agent-image pin';
  const file = path.join(target, 'versions.json');

  let raw: string;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch {
    return {
      name,
      level: 'skip',
      detail: `no versions.json under ${target} — is this a NanoClaw checkout?`,
      enforcement: 'unenforced',
    };
  }

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return {
      name,
      level: 'fail',
      detail: `could not parse ${file} as JSON: ${err instanceof Error ? err.message : String(err)}`,
      remediation: "fix the file's JSON syntax — this is the file that decides which image your agents run",
      enforcement: 'unenforced',
    };
  }

  const image = parsed['agent-image'];
  if (typeof image !== 'string' || image === '') {
    return {
      name,
      level: 'warn',
      detail: `${file} names no agent-image — nothing here pins what the agent containers run, so whatever the build or pull resolves to at the time is what executes`,
      remediation: 'pin agent-image to a digest (`<repo>@sha256:<64 hex>`), not a tag',
      enforcement: 'unenforced',
    };
  }

  if (DIGEST_PIN.test(image)) {
    return {
      name,
      level: 'pass',
      detail: `${file} pins agent-image by digest (${image.slice(image.indexOf('@sha256:'), image.indexOf('@sha256:') + 19)}…) — the exact bytes are fixed, and a repointed tag cannot change what runs`,
      enforcement: 'nanoclaw-native',
    };
  }

  const tag = image.includes(':') ? image.slice(image.lastIndexOf(':') + 1) : '(no tag)';
  return {
    name,
    level: 'warn',
    detail: `${file} pins agent-image by tag, not digest: ${image}. The tag "${tag}" can be repointed at different bytes at any time, with nothing in this checkout changing — so what your agents execute is not actually pinned by this file.`,
    remediation:
      'resolve the tag to a digest and pin that instead (`docker image inspect <image> --format "{{index .RepoDigests 0}}"`), then re-pin deliberately when you want to move it',
    enforcement: 'unenforced',
  };
}
