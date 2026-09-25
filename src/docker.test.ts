import { describe, expect, it } from 'vitest';

import { FakeDockerRunner, RealDockerRunner } from './docker.js';

describe('the read-only allowlist', () => {
  const runner = new FakeDockerRunner({});

  it('permits the read-only subcommands the checks use', () => {
    for (const args of [
      ['info', '--format', '{{.ServerVersion}}'],
      ['ps', '--filter', 'label=nanoclaw-session'],
      ['inspect', '--format', 'x', 'abc'],
      ['image', 'inspect', 'img'],
      ['network', 'inspect', 'nanoclaw-egress'],
      ['network', 'ls'],
      ['version'],
    ]) {
      expect(() => runner.run(args)).not.toThrow();
    }
  });

  // The point of the allowlist: a future edit that reaches for a mutating
  // command fails loudly instead of quietly making the README a lie.
  it('refuses anything that could change something', () => {
    for (const args of [
      ['network', 'create', '--internal', 'x'],
      ['network', 'connect', 'net', 'c'],
      ['network', 'rm', 'x'],
      ['run', '--network', 'host', '--cap-add', 'NET_ADMIN', 'alpine'],
      ['exec', 'container', 'sh'],
      ['create', 'alpine'],
      ['rm', '-f', 'container'],
      ['pull', 'alpine'],
      ['image', 'rm', 'img'],
      ['build', '.'],
    ]) {
      expect(() => runner.run(args)).toThrow(/read-only/);
    }
  });

  it('matches on the full subcommand prefix, not just the first word', () => {
    expect(() => runner.run(['network', 'inspect', 'x'])).not.toThrow();
    expect(() => runner.run(['network', 'create', 'x'])).toThrow(/read-only/);
  });

  it('refuses an empty argument list', () => {
    expect(() => runner.run([])).toThrow(/read-only/);
  });

  it('applies to the real runner too, before anything is executed', () => {
    // Would throw from the allowlist, never reaching execFileSync.
    expect(() => new RealDockerRunner().run(['run', 'alpine'])).toThrow(/read-only/);
  });
});

describe('FakeDockerRunner', () => {
  it('answers from its table and records calls', () => {
    const runner = new FakeDockerRunner({ 'network ls': { ok: true, stdout: 'bridge', stderr: '' } });
    expect(runner.run(['network', 'ls']).stdout).toBe('bridge');
    expect(runner.calls).toEqual([['network', 'ls']]);
  });

  it('reports a miss as a failure rather than a silent empty success', () => {
    const r = new FakeDockerRunner({}).run(['network', 'ls']);
    expect(r.ok).toBe(false);
  });

  it('can present an unavailable daemon', () => {
    expect(new FakeDockerRunner({}, false).available()).toBe(false);
  });
});

describe('RealDockerRunner', () => {
  it('reports a failure instead of throwing when docker is absent or the daemon is down', () => {
    // Either outcome is fine on a given machine; what matters is that it
    // returns a result rather than throwing, so a check can report `skip`.
    const runner = new RealDockerRunner();
    expect(() => runner.available()).not.toThrow();
    expect(typeof runner.available()).toBe('boolean');
  });
});
