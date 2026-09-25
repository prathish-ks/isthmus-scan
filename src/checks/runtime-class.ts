/**
 * Reports whether agent containers get a hardened runtime class (gVisor, Kata
 * Containers, Sysbox) instead of the shared-host-kernel default.
 *
 * A near-verbatim port of Isthmus's `doctor.checkRuntimeClass`
 * (go-host/internal/doctor/doctor.go, ADR-021) — including, deliberately, its
 * posture, which is the part worth copying:
 *
 *   This check REPORTS, it does not demand. Neither NanoClaw nor Isthmus
 *   implements microVM or user-space-kernel isolation of its own, and which
 *   runtimes a daemon offers is a deployment decision made outside either
 *   project. So "no hardened runtime available" is a PASS with a plainly
 *   worded detail, not a warning. Warning every personal install about a gap
 *   it was never promised would be noise an operator cannot honestly act on.
 *
 * The one case that does warrant attention, and so warns, is a hardened
 * runtime that is installed but is not the one containers actually get.
 *
 * One `docker info` call. It spawns nothing and changes nothing — the same
 * cost as asking whether the daemon is up at all.
 */
import type { CheckResult } from '../report.js';
import { DAEMON_UNREACHABLE_DETAIL, type DockerRunner } from '../docker.js';

const CHECK_NAME = 'container runtime class';

/**
 * Asks, in one call, for the default runtime and every runtime the daemon
 * knows about: "<default>;<name> <name> ".
 */
const RUNTIME_FORMAT = '{{.DefaultRuntime}};{{range $name, $_ := .Runtimes}}{{$name}} {{end}}';

/**
 * Maps a lowercase substring of a runtime's name to the name it is reported
 * under. Substring matching because the same runtime appears under several
 * spellings depending on how it was installed — gVisor is `runsc` as a Docker
 * runtime but `io.containerd.runsc.v1` as a containerd shim; Kata is `kata`,
 * `kata-runtime` or `io.containerd.kata.v2`. Anything not listed (`runc`,
 * `crun`, `io.containerd.runc.v2`, `nvidia`) shares the host kernel and is
 * reported as exactly that, never guessed about.
 */
const HARDENED_RUNTIMES: { match: string; name: string }[] = [
  { match: 'runsc', name: 'gVisor' },
  { match: 'gvisor', name: 'gVisor' },
  { match: 'kata', name: 'Kata Containers' },
  { match: 'sysbox', name: 'Sysbox' },
];

export function hardenedRuntimeName(runtime: string): string | null {
  const lower = runtime.toLowerCase();
  return HARDENED_RUNTIMES.find((h) => lower.includes(h.match))?.name ?? null;
}

export function checkRuntimeClass(docker: DockerRunner): CheckResult {
  if (!docker.available()) {
    return {
      name: CHECK_NAME,
      level: 'skip',
      detail: `${DAEMON_UNREACHABLE_DETAIL}. Which runtime class your containers get is a property of the daemon, so there is nothing to read from files.`,
      enforcement: 'unenforced',
    };
  }

  const info = docker.run(['info', '--format', RUNTIME_FORMAT]);
  const [rawDefault, rawList] = info.stdout.split(';');
  const defaultRuntime = (rawDefault ?? '').trim();

  if (!info.ok || rawList === undefined || defaultRuntime === '') {
    // Deliberately a skip, not a failure: whether the daemon is reachable at
    // all was already answered above, and this check has nothing of its own to
    // report when it cannot see the runtime list.
    return {
      name: CHECK_NAME,
      level: 'skip',
      detail:
        'the daemon did not answer `docker info` with a parseable runtime list, so the runtime class was not determined',
      enforcement: 'unenforced',
    };
  }

  const hardenedDefault = hardenedRuntimeName(defaultRuntime);
  if (hardenedDefault) {
    return {
      name: CHECK_NAME,
      level: 'pass',
      detail: `the daemon's default runtime is ${defaultRuntime} (${hardenedDefault}), a hardened runtime class — agent containers do not share the host kernel`,
      enforcement: 'nanoclaw-native',
    };
  }

  const availableHardened = rawList
    .split(/\s+/)
    .filter((n) => n !== '')
    .map((n) => ({ runtime: n, hardened: hardenedRuntimeName(n) }))
    .filter((r): r is { runtime: string; hardened: string } => r.hardened !== null)
    .map((r) => `${r.runtime} (${r.hardened})`);

  if (availableHardened.length > 0) {
    return {
      name: CHECK_NAME,
      level: 'warn',
      detail: `this daemon has a hardened runtime installed — ${availableHardened.join(', ')} — but its default runtime is ${defaultRuntime}, so agent containers still share the host kernel`,
      remediation:
        "set that runtime as the daemon's `default-runtime` in daemon.json (or run agent containers with `--runtime`) if the hardened one was installed for this host — this scan reports the runtime class, it never selects one for you",
      enforcement: 'unenforced',
    };
  }

  return {
    name: CHECK_NAME,
    level: 'pass',
    detail: `no hardened runtime class (gVisor, Kata Containers, Sysbox) is available to this daemon — agent containers run under ${defaultRuntime} and share the host kernel. That is the expected default for a personal install: neither NanoClaw nor Isthmus provides microVM or user-space-kernel isolation of its own, and neither claims any.`,
    enforcement: 'unenforced',
  };
}
