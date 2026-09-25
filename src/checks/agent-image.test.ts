import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { checkAgentImagePin } from './agent-image.js';

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
