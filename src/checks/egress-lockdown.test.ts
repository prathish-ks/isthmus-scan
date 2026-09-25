import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { checkEgressLockdownWiring, readLockdownConfig } from './egress-lockdown.js';
import { FakeDockerRunner, type DockerResult } from '../docker.js';

let dir: string;
const saved: Record<string, string | undefined> = {};
const VARS = ['NANOCLAW_EGRESS_LOCKDOWN', 'NANOCLAW_EGRESS_NETWORK', 'NANOCLAW_KERNEL_DOCKER_NETWORK'];

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'isthmus-scan-egress-test-'));
  for (const v of VARS) {
    saved[v] = process.env[v];
    delete process.env[v];
  }
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
  for (const v of VARS) {
    if (saved[v] === undefined) delete process.env[v];
    else process.env[v] = saved[v]!;
  }
});

const NET = 'nanoclaw-egress';
const ok = (stdout: string): DockerResult => ({ ok: true, stdout, stderr: '' });
const failed = (): DockerResult => ({ ok: false, stdout: '', stderr: 'no such thing' });

const INTERNAL_KEY = `network inspect ${NET} --format {{.Internal}}`;
const NET_KEY = `network inspect ${NET} --format {{range .Containers}}{{.Name}} {{end}}`;
const PS_KEY = 'ps --filter label=nanoclaw-session --format {{.ID}}';
const INSPECT_FORMAT =
  '{{.Name}}\t{{index .Config.Labels "nanoclaw-session"}}\t{{index .Config.Labels "nanoclaw-role"}}\t{{range $n, $_ := .NetworkSettings.Networks}}{{$n}} {{end}}';

/** A fake daemon: the egress network plus a set of running session containers. */
function daemon(opts: {
  networkExists?: boolean;
  internal?: boolean;
  attached?: string[];
  containers?: { name: string; session: string; role: string; networks: string[] }[];
  psFails?: boolean;
}): FakeDockerRunner {
  const { networkExists = true, internal = true, attached = ['onecli'], containers = [], psFails = false } = opts;
  const ids = containers.map((_, i) => `id${i}`);
  const responses: Record<string, DockerResult> = {
    'info --format {{.ServerVersion}}': ok('27.0.0'),
    [INTERNAL_KEY]: networkExists ? ok(String(internal)) : failed(),
    [NET_KEY]: networkExists ? ok(`${attached.join(' ')} `) : failed(),
    [PS_KEY]: psFails ? failed() : ok(ids.join('\n')),
  };
  if (ids.length > 0) {
    responses[['inspect', '--format', INSPECT_FORMAT, ...ids].join(' ')] = ok(
      containers.map((c) => `/${c.name}\t${c.session}\t${c.role}\t${c.networks.join(' ')} `).join('\n'),
    );
  }
  return new FakeDockerRunner(responses);
}

const agent = (name: string, networks: string[], session = 's1') => ({
  name,
  session,
  role: 'agent',
  networks,
});

describe('readLockdownConfig', () => {
  it('defaults to off with the stock network name', () => {
    expect(readLockdownConfig(dir)).toMatchObject({ lockdownOn: false, network: NET, origin: 'default' });
  });

  it('reads the flag from the environment', () => {
    process.env.NANOCLAW_EGRESS_LOCKDOWN = 'true';
    expect(readLockdownConfig(dir)).toMatchObject({ lockdownOn: true, origin: 'env' });
  });

  it('reads the flag from .env, which the host honors but never exports', () => {
    fs.writeFileSync(path.join(dir, '.env'), 'NANOCLAW_EGRESS_LOCKDOWN=true\n');
    expect(readLockdownConfig(dir)).toMatchObject({ lockdownOn: true, origin: 'dotenv' });
  });

  it('prefers a real env var over .env', () => {
    fs.writeFileSync(path.join(dir, '.env'), 'NANOCLAW_EGRESS_LOCKDOWN=true\n');
    process.env.NANOCLAW_EGRESS_LOCKDOWN = 'false';
    expect(readLockdownConfig(dir)).toMatchObject({ lockdownOn: false, origin: 'env' });
  });

  it('reads a custom network name from .env', () => {
    fs.writeFileSync(path.join(dir, '.env'), 'NANOCLAW_EGRESS_NETWORK=custom-net\n');
    expect(readLockdownConfig(dir).network).toBe('custom-net');
  });

  it('treats any value other than the literal true as off, matching config.ts', () => {
    process.env.NANOCLAW_EGRESS_LOCKDOWN = '1';
    expect(readLockdownConfig(dir).lockdownOn).toBe(false);
  });
});

describe('checkEgressLockdownWiring', () => {
  it('skips when lockdown is off, deferring to the cloud-metadata check', () => {
    const r = checkEgressLockdownWiring(dir, daemon({}));
    expect(r.level).toBe('skip');
    expect(r.detail).toContain('no lockdown to verify');
  });

  describe('with lockdown on', () => {
    beforeEach(() => {
      process.env.NANOCLAW_EGRESS_LOCKDOWN = 'true';
    });

    it('PASSES when every running agent is on the internal network', () => {
      const r = checkEgressLockdownWiring(
        dir,
        daemon({ attached: ['onecli', 'agent-1'], containers: [agent('agent-1', [NET])] }),
      );
      expect(r.level).toBe('pass');
      expect(r.detail).toContain('not merely configured');
      expect(r.enforcement).toBe('nanoclaw-native');
    });

    it('FAILS when an agent is on bridge with no sibling to explain it — the ADR-024 bug', () => {
      const r = checkEgressLockdownWiring(dir, daemon({ containers: [agent('agent-1', ['bridge'])] }));
      expect(r.level).toBe('fail');
      expect(r.detail).toContain('agent-1');
      expect(r.detail).toContain('open egress');
      // The whole point: docker network ls would have looked fine.
      expect(r.detail).toContain('docker network ls');
      expect(r.enforcement).toBe('unenforced');
    });

    it('downgrades to WARN when the agents session has a non-agent sibling', () => {
      // An in-session gateway legitimately gets no --network flag upstream, so
      // a bridge attachment there is not conclusive.
      const r = checkEgressLockdownWiring(
        dir,
        daemon({
          containers: [
            agent('agent-1', ['bridge'], 's1'),
            { name: 'proxy-1', session: 's1', role: 'gateway', networks: ['bridge'] },
          ],
        }),
      );
      expect(r.level).toBe('warn');
      expect(r.detail).toContain('inconclusive');
      expect(r.detail).toContain('in-session gateway');
    });

    it('still FAILS an unexplained agent even when another session has a sibling', () => {
      const r = checkEgressLockdownWiring(
        dir,
        daemon({
          containers: [
            agent('lonely', ['bridge'], 's1'),
            agent('paired', ['bridge'], 's2'),
            { name: 'proxy', session: 's2', role: 'gateway', networks: ['bridge'] },
          ],
        }),
      );
      expect(r.level).toBe('fail');
      expect(r.detail).toContain('lonely');
      expect(r.detail).not.toContain('paired');
    });

    it('FAILS when the network does not exist at all', () => {
      const r = checkEgressLockdownWiring(dir, daemon({ networkExists: false }));
      expect(r.level).toBe('fail');
      expect(r.detail).toContain('does not exist');
    });

    it('FAILS when the network exists but is not internal — correct by name, open in fact', () => {
      const r = checkEgressLockdownWiring(dir, daemon({ internal: false, containers: [agent('a', [NET])] }));
      expect(r.level).toBe('fail');
      expect(r.detail).toContain('NOT an internal network');
      expect(r.detail).toContain('route out');
    });

    it('FAILS on a conflicting kernel network override, without needing Docker', () => {
      process.env.NANOCLAW_KERNEL_DOCKER_NETWORK = 'something-else';
      const r = checkEgressLockdownWiring(dir, new FakeDockerRunner({}, false));
      expect(r.level).toBe('fail');
      expect(r.detail).toContain('refuses to start');
      expect(r.remediation).toContain('NANOCLAW_KERNEL_DOCKER_NETWORK');
    });

    it('accepts a kernel override that agrees with the egress network', () => {
      process.env.NANOCLAW_KERNEL_DOCKER_NETWORK = NET;
      const r = checkEgressLockdownWiring(dir, daemon({ containers: [agent('a', [NET])] }));
      expect(r.level).toBe('pass');
    });

    it('SKIPS rather than guessing when the daemon is unreachable', () => {
      const r = checkEgressLockdownWiring(dir, new FakeDockerRunner({}, false));
      expect(r.level).toBe('skip');
      expect(r.detail).toContain('cannot be confirmed from configuration alone');
    });

    it('reports INFO when no agent is running, since there is no attachment to verify', () => {
      const r = checkEgressLockdownWiring(dir, daemon({ containers: [] }));
      expect(r.level).toBe('info');
      expect(r.detail).toContain('No agent container is running');
    });

    it('ignores non-agent containers when deciding whether agents are attached', () => {
      const r = checkEgressLockdownWiring(
        dir,
        daemon({
          attached: ['onecli'],
          containers: [{ name: 'sidecar', session: 's1', role: 'gateway', networks: ['bridge'] }],
        }),
      );
      // Only a gateway is running, no agent — nothing to verify, not a failure.
      expect(r.level).toBe('info');
    });

    it('WARNS — never passes — when the container list cannot be read', () => {
      const r = checkEgressLockdownWiring(dir, daemon({ psFails: true }));
      expect(r.level).toBe('warn');
      expect(r.detail).toContain('not the same as anything using it');
    });

    it('notes when agents are isolated but no gateway appears attached', () => {
      const r = checkEgressLockdownWiring(dir, daemon({ attached: ['agent-1'], containers: [agent('agent-1', [NET])] }));
      expect(r.level).toBe('pass');
      expect(r.detail).toContain('no separate gateway container appears attached');
    });

    it('honors a custom network name throughout', () => {
      process.env.NANOCLAW_EGRESS_NETWORK = 'custom-net';
      const runner = new FakeDockerRunner({
        'info --format {{.ServerVersion}}': ok('27.0.0'),
        'network inspect custom-net --format {{.Internal}}': ok('true'),
        'network inspect custom-net --format {{range .Containers}}{{.Name}} {{end}}': ok('onecli agent-1 '),
        [PS_KEY]: ok('id0'),
        [['inspect', '--format', INSPECT_FORMAT, 'id0'].join(' ')]: ok('/agent-1\ts1\tagent\tcustom-net '),
      });
      expect(checkEgressLockdownWiring(dir, runner).level).toBe('pass');
    });
  });
});
