import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { checkAgentImagePin } from './agent-image.js';
import { FakeDockerRunner } from '../docker.js';

let dir: string;

/** Upstream NanoClaw v2.4.0's real versions.json pin. */
const UPSTREAM_PIN =
  '797273591697.dkr.ecr.us-east-1.amazonaws.com/nanoclaw/agent@sha256:79ac5063af36c1a77560a8aff66bc5efec8295b004fef32855a1df93fec3ea1a';

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'isthmus-scan-image-test-'));
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function writeVersions(content: unknown): void {
  fs.writeFileSync(path.join(dir, 'versions.json'), typeof content === 'string' ? content : JSON.stringify(content));
}

describe('checkAgentImagePin', () => {
  it('passes on upstreams real digest pin', () => {
    writeVersions({ 'agent-image': UPSTREAM_PIN });
    const r = checkAgentImagePin(dir);
    expect(r.level).toBe('pass');
    expect(r.enforcement).toBe('nanoclaw-native');
    expect(r.detail).toContain('@sha256:79ac5063');
  });

  it('warns on a floating tag, and says what that actually means', () => {
    writeVersions({ 'agent-image': 'nanoclaw/agent:latest' });
    const r = checkAgentImagePin(dir);
    expect(r.level).toBe('warn');
    expect(r.detail).toContain('"latest" can be repointed');
    expect(r.enforcement).toBe('unenforced');
  });

  it('warns on a bare repository with no tag or digest', () => {
    writeVersions({ 'agent-image': 'nanoclaw/agent' });
    expect(checkAgentImagePin(dir).level).toBe('warn');
  });

  it('does not accept a truncated or malformed digest', () => {
    writeVersions({ 'agent-image': 'nanoclaw/agent@sha256:abc123' });
    expect(checkAgentImagePin(dir).level).toBe('warn');
  });

  it('does not accept a digest with trailing content after it', () => {
    writeVersions({ 'agent-image': `${UPSTREAM_PIN}-suffix` });
    expect(checkAgentImagePin(dir).level).toBe('warn');
  });

  it('warns when agent-image is absent', () => {
    writeVersions({ 'onecli-cli': '2.2.5' });
    const r = checkAgentImagePin(dir);
    expect(r.level).toBe('warn');
    expect(r.detail).toContain('names no agent-image');
  });

  it('warns when agent-image is an empty string', () => {
    writeVersions({ 'agent-image': '' });
    expect(checkAgentImagePin(dir).level).toBe('warn');
  });

  it('fails on unparseable JSON rather than reporting the pin as absent', () => {
    writeVersions('{not json');
    const r = checkAgentImagePin(dir);
    expect(r.level).toBe('fail');
    expect(r.detail).toContain('could not parse');
  });

  it('skips when there is no versions.json at all', () => {
    expect(checkAgentImagePin(dir).level).toBe('skip');
  });
});

describe('checkAgentImagePin with a Docker daemon', () => {
  const up = { 'info --format {{.ServerVersion}}': { ok: true, stdout: '27.0.0', stderr: '' } };
  const DIGEST_FMT = '{{range .RepoDigests}}{{.}}{{"\n"}}{{end}}';

  it('confirms a digest-pinned image is present on this machine', () => {
    const docker = new FakeDockerRunner({
      ...up,
      [`image inspect ${UPSTREAM_PIN} --format ${DIGEST_FMT}`]: { ok: true, stdout: UPSTREAM_PIN, stderr: '' },
    });
    writeVersions({ 'agent-image': UPSTREAM_PIN });
    const r = checkAgentImagePin(dir, docker);
    expect(r.level).toBe('pass');
    expect(r.detail).toContain('present on this machine');
  });

  it('still passes a correct digest pin whose image has not been pulled yet', () => {
    const docker = new FakeDockerRunner(up);
    writeVersions({ 'agent-image': UPSTREAM_PIN });
    const r = checkAgentImagePin(dir, docker);
    expect(r.level).toBe('pass');
    expect(r.detail).toContain('not present locally yet');
  });

  it('turns a tag warning into an actionable pin by resolving the digest', () => {
    const digest = 'sha256:' + 'a'.repeat(64);
    const docker = new FakeDockerRunner({
      ...up,
      [`image inspect nanoclaw/agent:latest --format ${DIGEST_FMT}`]: {
        ok: true,
        stdout: `nanoclaw/agent@${digest}`,
        stderr: '',
      },
    });
    writeVersions({ 'agent-image': 'nanoclaw/agent:latest' });
    const r = checkAgentImagePin(dir, docker);
    expect(r.level).toBe('warn');
    expect(r.detail).toContain(`currently resolves to ${digest}`);
    expect(r.remediation).toContain(`nanoclaw/agent@${digest}`);
  });

  it('falls back to the generic advice when the tag is not present locally', () => {
    writeVersions({ 'agent-image': 'nanoclaw/agent:latest' });
    const r = checkAgentImagePin(dir, new FakeDockerRunner(up));
    expect(r.level).toBe('warn');
    expect(r.remediation).toContain('resolve the tag to a digest');
  });

  it('never asks Docker when the daemon is down, and the static verdict stands', () => {
    const docker = new FakeDockerRunner({}, false);
    writeVersions({ 'agent-image': UPSTREAM_PIN });
    const r = checkAgentImagePin(dir, docker);
    expect(r.level).toBe('pass');
    expect(r.detail).not.toContain('present on this machine');
    expect(r.detail).not.toContain('not present locally yet');
    expect(docker.calls).toHaveLength(0);
  });
});
