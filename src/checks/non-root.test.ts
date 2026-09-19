import fs from 'fs';
import path from 'path';
import os from 'os';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { checkNonRoot } from './non-root.js';

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'isthmus-scan-nonroot-test-'));
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function writeDockerfile(content: string): void {
  fs.mkdirSync(path.join(dir, 'container'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'container', 'Dockerfile'), content);
}

describe('checkNonRoot', () => {
  it('skips when no Dockerfile is found at all', () => {
    expect(checkNonRoot(dir).level).toBe('skip');
  });

  it('fails when there is no USER directive', () => {
    writeDockerfile('FROM node:22-slim\nRUN echo hi\n');
    expect(checkNonRoot(dir).level).toBe('fail');
  });

  it('fails when the last USER directive is root', () => {
    writeDockerfile('FROM node:22-slim\nUSER node\nRUN echo hi\nUSER root\n');
    const result = checkNonRoot(dir);
    expect(result.level).toBe('fail');
    expect(result.detail).toContain('root');
  });

  it('fails when the last USER directive is uid 0', () => {
    writeDockerfile('FROM node:22-slim\nUSER 0\n');
    expect(checkNonRoot(dir).level).toBe('fail');
  });

  it('passes when the last USER directive is non-root', () => {
    writeDockerfile('FROM node:22-slim\nUSER root\nRUN echo hi\nUSER node\n');
    const result = checkNonRoot(dir);
    expect(result.level).toBe('pass');
    expect(result.detail).toContain("'node'");
  });

  it('falls back to a root-level Dockerfile when container/Dockerfile is absent', () => {
    fs.writeFileSync(path.join(dir, 'Dockerfile'), 'FROM node:22-slim\nUSER app\n');
    expect(checkNonRoot(dir).level).toBe('pass');
  });
});
