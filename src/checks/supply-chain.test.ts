import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { checkInstallScriptAllowlist, checkReleaseAgeGate } from './supply-chain.js';

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'isthmus-scan-supply-test-'));
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function write(file: string, content: string): void {
  fs.writeFileSync(path.join(dir, file), content);
}

/** Upstream NanoClaw v2.4.0's actual pnpm-workspace.yaml shape — the fixed, hoisted form. */
const UPSTREAM_YAML = `onlyBuiltDependencies:
  - esbuild
  - protobufjs
  - sharp

# Top-level, NOT nested under a \`pnpm:\` key.
minimumReleaseAge: 4320
`;

/** The Isthmus fork's actual shape — the nested, silently-inert form. */
const FORK_YAML = `onlyBuiltDependencies:
  - esbuild
  - protobufjs
  - sharp

pnpm:
  minimumReleaseAge: 4320
`;

describe('checkReleaseAgeGate', () => {
  it('passes on upstream NanoClaw v2.4.0s real config', () => {
    write('pnpm-workspace.yaml', UPSTREAM_YAML);
    write('.npmrc', 'minReleaseAge=3d\n');
    const r = checkReleaseAgeGate(dir);
    expect(r.level).toBe('pass');
    expect(r.enforcement).toBe('nanoclaw-native');
    expect(r.detail).toContain('3 days');
  });

  it('FAILS on the nested form, which looks configured and is a no-op', () => {
    write('pnpm-workspace.yaml', FORK_YAML);
    write('.npmrc', 'minReleaseAge=3d\n');
    const r = checkReleaseAgeGate(dir);
    expect(r.level).toBe('fail');
    // The value being correct is precisely what makes this dangerous.
    expect(r.detail).toContain('4320');
    expect(r.detail).toContain('silently ignored');
    expect(r.detail).toContain('no-op');
    expect(r.remediation).toContain('pnpm config get minimumReleaseAge');
    // Nothing is enforcing a gate pnpm never reads.
    expect(r.enforcement).toBe('unenforced');
  });

  it('names the nesting path and line so the fix is unambiguous', () => {
    write('pnpm-workspace.yaml', FORK_YAML);
    const r = checkReleaseAgeGate(dir);
    expect(r.detail).toContain('pnpm');
    expect(r.detail).toContain('line 7');
  });

  it('warns when the key is absent entirely', () => {
    write('pnpm-workspace.yaml', 'onlyBuiltDependencies:\n  - esbuild\n');
    const r = checkReleaseAgeGate(dir);
    expect(r.level).toBe('warn');
    expect(r.detail).toContain('no minimumReleaseAge');
  });

  it('warns when the window is below the documented 3 days', () => {
    write('pnpm-workspace.yaml', 'minimumReleaseAge: 60\n');
    write('.npmrc', 'minReleaseAge=3d\n');
    const r = checkReleaseAgeGate(dir);
    expect(r.level).toBe('warn');
    expect(r.detail).toContain('below the 4320');
  });

  it('flags an inert nested copy sitting beside a live top-level one', () => {
    write('pnpm-workspace.yaml', 'minimumReleaseAge: 4320\npnpm:\n  minimumReleaseAge: 10\n');
    write('.npmrc', 'minReleaseAge=3d\n');
    const r = checkReleaseAgeGate(dir);
    expect(r.level).toBe('warn');
    expect(r.detail).toContain("a reader won't");
  });

  it('warns about a missing .npmrc fallback even when the gate itself is live', () => {
    write('pnpm-workspace.yaml', UPSTREAM_YAML);
    const r = checkReleaseAgeGate(dir);
    expect(r.level).toBe('warn');
    expect(r.detail).toContain('no minReleaseAge fallback');
  });

  it('warns on an exact-pinned exclusion, which is allowed but should be rare', () => {
    write('pnpm-workspace.yaml', `${UPSTREAM_YAML}minimumReleaseAgeExclude:\n  some-package: "1.2.3"\n`);
    write('.npmrc', 'minReleaseAge=3d\n');
    const r = checkReleaseAgeGate(dir);
    expect(r.level).toBe('warn');
    expect(r.detail).toContain('some-package@1.2.3');
  });

  it('FAILS on a range-shaped exclusion, which the docs forbid', () => {
    write('pnpm-workspace.yaml', `${UPSTREAM_YAML}minimumReleaseAgeExclude:\n  some-package: "^1.2.3"\n`);
    write('.npmrc', 'minReleaseAge=3d\n');
    const r = checkReleaseAgeGate(dir);
    expect(r.level).toBe('fail');
    expect(r.detail).toContain('never a range or wildcard');
  });

  it('skips when there is no pnpm-workspace.yaml at all', () => {
    expect(checkReleaseAgeGate(dir).level).toBe('skip');
  });

  it('warns — never "absent" — when the file cannot be read confidently', () => {
    write('pnpm-workspace.yaml', 'pnpm: { minimumReleaseAge: 4320 }\n');
    const r = checkReleaseAgeGate(dir);
    expect(r.level).toBe('warn');
    expect(r.detail).toContain('gave up rather than proving anything');
    expect(r.detail).not.toContain('sets no minimumReleaseAge');
  });
});

describe('checkInstallScriptAllowlist', () => {
  it('passes on upstreams own set', () => {
    write('pnpm-workspace.yaml', UPSTREAM_YAML);
    const r = checkInstallScriptAllowlist(dir);
    expect(r.level).toBe('pass');
    expect(r.enforcement).toBe('nanoclaw-native');
  });

  it('warns about a locally added build script, naming it', () => {
    write('pnpm-workspace.yaml', 'onlyBuiltDependencies:\n  - esbuild\n  - some-sketchy-pkg\n');
    const r = checkInstallScriptAllowlist(dir);
    expect(r.level).toBe('warn');
    expect(r.detail).toContain('some-sketchy-pkg');
    expect(r.detail).not.toContain('esbuild,');
    expect(r.remediation).toContain('approved by a human');
  });

  it('warns when the allowlist is missing entirely', () => {
    write('pnpm-workspace.yaml', 'minimumReleaseAge: 4320\n');
    const r = checkInstallScriptAllowlist(dir);
    expect(r.level).toBe('warn');
    expect(r.detail).toContain('no onlyBuiltDependencies');
  });

  it('does not read the allowlist out of a nested block by accident', () => {
    // A nested onlyBuiltDependencies is a different question from
    // minimumReleaseAge's; pnpm does read this one from the workspace file,
    // so finding it at any depth is correct here.
    write('pnpm-workspace.yaml', 'onlyBuiltDependencies:\n  - esbuild\n');
    expect(checkInstallScriptAllowlist(dir).level).toBe('pass');
  });

  it('warns — never "empty" — when the file cannot be read confidently', () => {
    write('pnpm-workspace.yaml', 'onlyBuiltDependencies: [esbuild]\n');
    const r = checkInstallScriptAllowlist(dir);
    expect(r.level).toBe('warn');
    expect(r.detail).toContain('gave up rather than proving anything');
  });

  it('skips when there is no pnpm-workspace.yaml at all', () => {
    expect(checkInstallScriptAllowlist(dir).level).toBe('skip');
  });
});
