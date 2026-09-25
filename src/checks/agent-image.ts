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
 * When a Docker runner is supplied, one extra read-only `docker image inspect`
 * turns the tag case from a complaint into something actionable: it reports the
 * digest that tag currently resolves to on this machine, which is the value to
 * pin. Everything still works without a daemon — the static verdict stands and
 * the check says the live half was skipped.
 */
import fs from 'fs';
import path from 'path';

import type { CheckResult } from '../report.js';
import type { DockerRunner } from '../docker.js';

const DIGEST_PIN = /@sha256:[0-9a-f]{64}$/;

/**
 * The digest `reference` resolves to locally, or null when the image is not
 * present or Docker cannot be asked. RepoDigests, not .Id: .Id is the local
 * content id, while RepoDigests carries the registry digest a pin is written
 * against.
 */
function localDigest(reference: string, docker: DockerRunner | undefined): string | null {
  if (!docker?.available()) return null;
  const out = docker.run([
    'image',
    'inspect',
    reference,
    '--format',
    '{{range .RepoDigests}}{{.}}{{"\n"}}{{end}}',
  ]);
  if (!out.ok) return null;
  return out.stdout.match(/sha256:[0-9a-f]{64}/)?.[0] ?? null;
}

export function checkAgentImagePin(target: string, docker?: DockerRunner): CheckResult {
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
    const shortDigest = image.slice(image.indexOf('@sha256:'), image.indexOf('@sha256:') + 19);
    const present = localDigest(image, docker) !== null;
    const presenceNote = !docker?.available()
      ? ''
      : present
        ? ', and that exact image is present on this machine'
        : ' (not present locally yet — it resolves on the next pull or build, which the digest still fixes)';
    return {
      name,
      level: 'pass',
      detail: `${file} pins agent-image by digest (${shortDigest}…) — the exact bytes are fixed, and a repointed tag cannot change what runs${presenceNote}`,
      enforcement: 'nanoclaw-native',
    };
  }

  const tag = image.includes(':') ? image.slice(image.lastIndexOf(':') + 1) : '(no tag)';
  const resolved = localDigest(image, docker);
  return {
    name,
    level: 'warn',
    detail: `${file} pins agent-image by tag, not digest: ${image}. The tag "${tag}" can be repointed at different bytes at any time, with nothing in this checkout changing — so what your agents execute is not actually pinned by this file.${
      resolved ? ` On this machine that tag currently resolves to ${resolved}.` : ''
    }`,
    remediation: resolved
      ? `if that is the image you want, pin it: set agent-image to ${image.split(':')[0]}@${resolved}`
      : 'resolve the tag to a digest and pin that instead (`docker image inspect <image> --format "{{index .RepoDigests 0}}"`), then re-pin deliberately when you want to move it',
    enforcement: 'unenforced',
  };
}
