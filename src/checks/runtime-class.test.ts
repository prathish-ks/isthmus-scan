import { describe, expect, it } from 'vitest';

import { checkRuntimeClass, hardenedRuntimeName } from './runtime-class.js';
import { FakeDockerRunner } from '../docker.js';

const FORMAT = '{{.DefaultRuntime}};{{range $name, $_ := .Runtimes}}{{$name}} {{end}}';

function daemon(defaultRuntime: string, runtimes: string[]): FakeDockerRunner {
  return new FakeDockerRunner({
    'info --format {{.ServerVersion}}': { ok: true, stdout: '27.0.0', stderr: '' },
    [`info --format ${FORMAT}`]: { ok: true, stdout: `${defaultRuntime};${runtimes.join(' ')} `, stderr: '' },
  });
}

describe('hardenedRuntimeName', () => {
  it('recognizes each hardened runtime under every spelling it ships as', () => {
    expect(hardenedRuntimeName('runsc')).toBe('gVisor');
    expect(hardenedRuntimeName('io.containerd.runsc.v1')).toBe('gVisor');
    expect(hardenedRuntimeName('gvisor')).toBe('gVisor');
    expect(hardenedRuntimeName('kata')).toBe('Kata Containers');
    expect(hardenedRuntimeName('kata-runtime')).toBe('Kata Containers');
    expect(hardenedRuntimeName('io.containerd.kata.v2')).toBe('Kata Containers');
    expect(hardenedRuntimeName('sysbox-runc')).toBe('Sysbox');
  });

  it('is case-insensitive', () => {
    expect(hardenedRuntimeName('RunSC')).toBe('gVisor');
  });

  it('does not guess about ordinary shared-kernel runtimes', () => {
    for (const r of ['runc', 'crun', 'io.containerd.runc.v2', 'nvidia']) {
      expect(hardenedRuntimeName(r)).toBeNull();
    }
  });
});

describe('checkRuntimeClass', () => {
  it('passes when the default runtime is hardened', () => {
    const r = checkRuntimeClass(daemon('runsc', ['runc', 'runsc']));
    expect(r.level).toBe('pass');
    expect(r.detail).toContain('gVisor');
    expect(r.detail).toContain('do not share the host kernel');
    expect(r.enforcement).toBe('nanoclaw-native');
  });

  it('WARNS when a hardened runtime is installed but is not the default — the one actionable case', () => {
    const r = checkRuntimeClass(daemon('runc', ['runc', 'runsc']));
    expect(r.level).toBe('warn');
    expect(r.detail).toContain('runsc (gVisor)');
    expect(r.detail).toContain('still share the host kernel');
    expect(r.remediation).toContain('never selects one for you');
  });

  // The posture worth porting: a personal install was never promised microVM
  // isolation, so warning about its absence is noise it cannot act on.
  it('PASSES — does not warn — when no hardened runtime is available at all', () => {
    const r = checkRuntimeClass(daemon('runc', ['runc']));
    expect(r.level).toBe('pass');
    expect(r.detail).toContain('share the host kernel');
    expect(r.detail).toContain('expected default for a personal install');
    expect(r.enforcement).toBe('unenforced');
  });

  it('names several available hardened runtimes when the daemon has more than one', () => {
    const r = checkRuntimeClass(daemon('runc', ['runc', 'runsc', 'kata-runtime']));
    expect(r.level).toBe('warn');
    expect(r.detail).toContain('gVisor');
    expect(r.detail).toContain('Kata Containers');
  });

  it('skips when the daemon is unreachable', () => {
    const r = checkRuntimeClass(new FakeDockerRunner({}, false));
    expect(r.level).toBe('skip');
    expect(r.detail).toContain('did not answer');
  });

  it('skips — rather than failing — on an unparseable runtime list', () => {
    const runner = new FakeDockerRunner({
      'info --format {{.ServerVersion}}': { ok: true, stdout: '27.0.0', stderr: '' },
      [`info --format ${FORMAT}`]: { ok: true, stdout: 'garbage-with-no-separator', stderr: '' },
    });
    const r = checkRuntimeClass(runner);
    expect(r.level).toBe('skip');
    expect(r.detail).toContain('not determined');
  });

  it('skips on an empty default runtime', () => {
    expect(checkRuntimeClass(daemon('', ['runc'])).level).toBe('skip');
  });
});
