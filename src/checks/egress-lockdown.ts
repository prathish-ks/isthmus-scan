/**
 * Does egress lockdown actually reach your containers?
 *
 * `NANOCLAW_EGRESS_LOCKDOWN=true` is meant to put every agent container on an
 * isolated Docker `--internal` network with no route out except the gateway.
 * Inside Isthmus that silently stopped being true for an entire release cycle
 * (go-host/docs/ADR-024): the EC-02 refactor moved `docker create` behind the
 * Go kernel and orphaned the closure that appended `--network`, while
 * host-sweep kept creating and healing the network on its own 60-second tick.
 * So `docker network ls` showed exactly what an operator expected to see, and
 * every agent container sat on the default bridge with open egress.
 *
 * To be clear about whose bug that was: upstream NanoClaw's attach path is
 * live and per-spawn (src/drivers/index.ts's `dockerNetworkArgs` →
 * `ensureEgressNetwork` → `egressNetworkArgs`). This check is not telling an
 * upstream user they are broken. It is the regression detector that would have
 * caught the Isthmus break, and the only thing that distinguishes "lockdown is
 * configured" from "lockdown is happening".
 *
 * Every call here is read-only: `docker ps`, `docker inspect`, `docker network
 * inspect`. Nothing is created, nothing is executed in a container.
 */
import fs from 'fs';
import path from 'path';

import type { CheckResult, Enforcement } from '../report.js';
import { DAEMON_UNREACHABLE_DETAIL, type DockerRunner } from '../docker.js';

const CHECK_NAME = 'egress-lockdown wiring';

/** src/drivers/types.ts's LABELS, which every driver stamps onto every container. */
const SESSION_LABEL = 'nanoclaw-session';
const ROLE_LABEL = 'nanoclaw-role';
/** The one required role; an overlay's auxiliary containers bring their own names. */
const AGENT_ROLE = 'agent';

export interface LockdownConfig {
  lockdownOn: boolean;
  network: string;
  /** Isthmus-only: a kernel-startup network override that must not disagree with `network`. */
  kernelNetworkOverride?: string;
  /** Where each value came from, for a report an operator can act on. */
  origin: 'env' | 'dotenv' | 'default';
}

/** Reads one key from `<target>/.env` the way src/env.ts's readEnvFile does. */
function dotEnv(target: string, key: string): string | undefined {
  let content: string;
  try {
    content = fs.readFileSync(path.join(target, '.env'), 'utf8');
  } catch {
    return undefined;
  }
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1 || trimmed.slice(0, eq).trim() !== key) continue;
    let v = trimmed.slice(eq + 1).trim();
    if (v.length >= 2 && ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'")))) {
      v = v.slice(1, -1);
    }
    return v || undefined;
  }
  return undefined;
}

/**
 * Mirrors src/config.ts:114-116: `process.env` first, then `.env`, then the
 * default. Reading `.env` matters — readEnvFile never copies values into
 * process.env, so a lockdown enabled only there is invisible to anything that
 * checks the environment alone, which is also the known gap Isthmus's own Go
 * backstop documents (ADR-025).
 */
export function readLockdownConfig(target: string): LockdownConfig {
  const envFlag = process.env.NANOCLAW_EGRESS_LOCKDOWN;
  const dotFlag = dotEnv(target, 'NANOCLAW_EGRESS_LOCKDOWN');
  const origin: LockdownConfig['origin'] = envFlag !== undefined ? 'env' : dotFlag !== undefined ? 'dotenv' : 'default';
  return {
    lockdownOn: (envFlag ?? dotFlag) === 'true',
    network:
      process.env.NANOCLAW_EGRESS_NETWORK ?? dotEnv(target, 'NANOCLAW_EGRESS_NETWORK') ?? 'nanoclaw-egress',
    kernelNetworkOverride: process.env.NANOCLAW_KERNEL_DOCKER_NETWORK,
    origin,
  };
}

interface ContainerRow {
  name: string;
  session: string;
  role: string;
  networks: string[];
}

/**
 * Every live NanoClaw session container and the networks it is actually on.
 * `docker ps` alone cannot report networks, so this is a list followed by one
 * inspect over all ids.
 */
function listSessionContainers(docker: DockerRunner): ContainerRow[] | null {
  const ids = docker.run(['ps', '--filter', `label=${SESSION_LABEL}`, '--format', '{{.ID}}']);
  if (!ids.ok) return null;
  const idList = ids.stdout.split('\n').filter((l) => l.trim() !== '');
  if (idList.length === 0) return [];

  // Tab-separated, because a container name cannot contain a tab but a network
  // list is space-separated and would be ambiguous otherwise. The map-range
  // idiom is the same one Isthmus's doctor uses against `.Runtimes`; `.Name`
  // on a container comes back as "/name", stripped below.
  const format = `{{.Name}}\t{{index .Config.Labels "${SESSION_LABEL}"}}\t{{index .Config.Labels "${ROLE_LABEL}"}}\t{{range $n, $_ := .NetworkSettings.Networks}}{{$n}} {{end}}`;
  const inspected = docker.run(['inspect', '--format', format, ...idList]);
  if (!inspected.ok) return null;

  const rows: ContainerRow[] = [];
  for (const line of inspected.stdout.split('\n')) {
    if (line.trim() === '') continue;
    const [name, session, role, networks] = line.split('\t');
    rows.push({
      name: (name ?? '').replace(/^\//, ''),
      session: session ?? '',
      role: role ?? '',
      networks: (networks ?? '').split(/\s+/).filter((n) => n !== ''),
    });
  }
  return rows;
}

export function checkEgressLockdownWiring(target: string, docker: DockerRunner): CheckResult {
  const cfg = readLockdownConfig(target);

  if (!cfg.lockdownOn) {
    return {
      name: CHECK_NAME,
      level: 'skip',
      detail:
        'NANOCLAW_EGRESS_LOCKDOWN is not set to true, so there is no lockdown to verify. Egress is open by default — see the cloud-metadata check above for what that means.',
      enforcement: 'unenforced',
    };
  }

  // Static and conclusive, and it needs no daemon: Isthmus refuses to start
  // with these disagreeing (ADR-024), so catching it here beats hitting it at
  // kernel startup.
  if (cfg.kernelNetworkOverride && cfg.kernelNetworkOverride !== cfg.network) {
    return {
      name: CHECK_NAME,
      level: 'fail',
      detail: `lockdown is on and expects the network "${cfg.network}", but NANOCLAW_KERNEL_DOCKER_NETWORK is set to "${cfg.kernelNetworkOverride}". Isthmus's kernel refuses to start with these disagreeing rather than silently picking one, so this configuration does not run.`,
      remediation: `unset NANOCLAW_KERNEL_DOCKER_NETWORK, or set it to "${cfg.network}"`,
      enforcement: 'unenforced',
    };
  }

  if (!docker.available()) {
    return {
      name: CHECK_NAME,
      level: 'skip',
      detail: `lockdown is on (from ${cfg.origin === 'default' ? 'the environment' : cfg.origin}), but ${DAEMON_UNREACHABLE_DETAIL}. Whether your containers are actually on "${cfg.network}" is exactly what cannot be confirmed from configuration alone.`,
      remediation: 'start Docker and re-run, so this check can confirm the network attachment rather than assume it',
      enforcement: 'unenforced',
    };
  }

  // Two calls, each with a format string that already runs in production —
  // `{{.Internal}}` is a plain field, and the container range is verbatim from
  // upstream's own gatewayAttached (src/egress-lockdown.ts). A single combined
  // format would be shorter and would be the one thing here that nothing has
  // ever executed.
  const netInternal = docker.run(['network', 'inspect', cfg.network, '--format', '{{.Internal}}']);
  const netInspect = docker.run([
    'network',
    'inspect',
    cfg.network,
    '--format',
    '{{range .Containers}}{{.Name}} {{end}}',
  ]);

  if (!netInternal.ok || !netInspect.ok) {
    return {
      name: CHECK_NAME,
      level: 'fail',
      detail: `lockdown is on, but the "${cfg.network}" network does not exist. Nothing is isolating your agent containers — they are on whatever Docker gave them, with open egress.`,
      remediation:
        'start the host normally so it establishes the network (NanoClaw refuses to spawn rather than run open once it can see this), or set NANOCLAW_EGRESS_LOCKDOWN=false if you did not intend lockdown',
      enforcement: 'unenforced',
    };
  }

  const attached = netInspect.stdout.split(/\s+/).filter((n) => n !== '');
  const isInternal = netInternal.stdout.trim() === 'true';

  // A network that exists but was not created --internal has a route out. This
  // is the most deceptive state available: every name matches, and egress is open.
  if (!isInternal) {
    return {
      name: CHECK_NAME,
      level: 'fail',
      detail: `the "${cfg.network}" network exists but is NOT an internal network, so it has a route out. Containers on it look correctly isolated by name while having open egress — NanoClaw creates this network with --internal, so something else made this one.`,
      remediation: `remove the network and let the host recreate it: it must be created with \`--internal\` (\`docker network inspect ${cfg.network} --format '{{.Internal}}'\` should print true)`,
      enforcement: 'unenforced',
    };
  }

  const containers = listSessionContainers(docker);
  if (containers === null) {
    return {
      name: CHECK_NAME,
      level: 'warn',
      detail: `the "${cfg.network}" network exists and is internal, but this scan could not list running NanoClaw containers to confirm any are actually attached to it. The network existing is not the same as anything using it — that is the exact gap this check exists for.`,
      remediation: 'check by hand: `docker ps --filter label=nanoclaw-session` then `docker inspect <id> --format "{{json .NetworkSettings.Networks}}"`',
      enforcement: 'unenforced',
    };
  }

  const agents = containers.filter((c) => c.role === AGENT_ROLE);

  if (agents.length === 0) {
    const gatewayNote =
      attached.length > 0
        ? `${attached.length} container(s) are attached to it (${attached.join(', ')})`
        : 'nothing is attached to it';
    return {
      name: CHECK_NAME,
      level: 'info',
      detail: `lockdown is on, the "${cfg.network}" network exists and is internal, and ${gatewayNote}. No agent container is running right now, so there is no attachment to verify — re-run this while a session is live to confirm agents actually land on it.`,
      enforcement: 'unenforced',
    };
  }

  const onNetwork = agents.filter((a) => a.networks.includes(cfg.network));
  const offNetwork = agents.filter((a) => !a.networks.includes(cfg.network));

  if (offNetwork.length === 0) {
    const gatewayNote = attached.some((n) => !agents.some((a) => a.name === n))
      ? ' with a non-agent container (the gateway) attached alongside'
      : ', though no separate gateway container appears attached — agents are isolated, but check they can still reach the gateway';
    return {
      name: CHECK_NAME,
      level: 'pass',
      detail: `all ${onNetwork.length} running agent container(s) are attached to the internal "${cfg.network}" network${gatewayNote}. Lockdown is not merely configured — it is reaching your containers.`,
      enforcement: 'nanoclaw-native',
    };
  }

  // An agent legitimately gets no --network flag when its session's gateway is
  // a sibling container in the same session (upstream's
  // networkAccess.target.kind === 'session-container' returns no network args).
  // A sibling of a different role in the same session is the observable
  // signature of that composition, so it downgrades the verdict from a
  // conclusive leak to something a person has to look at.
  const ambiguous = offNetwork.filter((a) =>
    containers.some((c) => c.session === a.session && c.role !== AGENT_ROLE && c.name !== a.name),
  );
  const conclusive = offNetwork.filter((a) => !ambiguous.includes(a));

  if (conclusive.length > 0) {
    const level: Enforcement = 'unenforced';
    return {
      name: CHECK_NAME,
      level: 'fail',
      detail: `lockdown is on and the "${cfg.network}" network is correct, but ${conclusive.length} of ${agents.length} running agent container(s) are NOT attached to it:\n    ${conclusive.map((a) => `${a.name} — on ${a.networks.join(', ') || '(no network)'}`).join('\n    ')}\n  These have open egress. Nothing in \`docker network ls\` would show this, which is how the same bug went unnoticed for a release cycle in Isthmus (ADR-024).`,
      remediation:
        'restart the host so containers are recreated with the network attachment, and check the kernel is passing -docker-network (Isthmus) or that the driver still appends --network (plain NanoClaw)',
      enforcement: level,
    };
  }

  return {
    name: CHECK_NAME,
    level: 'warn',
    detail: `lockdown is on and the "${cfg.network}" network is correct, but ${ambiguous.length} of ${agents.length} running agent container(s) are not attached to it:\n    ${ambiguous.map((a) => `${a.name} — on ${a.networks.join(', ') || '(no network)'}`).join('\n    ')}\n  Each of these shares a session with a non-agent container, which is what an in-session gateway looks like — and that composition legitimately gets no --network flag. So this is inconclusive rather than a leak, and worth an operator's eye.`,
    remediation: `confirm those sessions route through their sibling gateway rather than straight out: \`docker inspect <name> --format '{{json .NetworkSettings.Networks}}'\``,
    enforcement: 'unenforced',
  };
}
