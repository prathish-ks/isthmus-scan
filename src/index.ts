#!/usr/bin/env node
/**
 * isthmus-scan — a free, read-only hardening scanner for NanoClaw installs.
 * https://github.com/prathish-ks/isthmus-scan
 *
 * Every check here is read-only. Most open files that already exist. The
 * kernel-liveness check makes one short-timeout local socket connection. The
 * rest ask the local Docker daemon what it already knows — `docker info`,
 * `docker ps`, `docker inspect` — which is how this tool can tell "lockdown is
 * configured" apart from "lockdown is happening". That read-only boundary is
 * enforced, not just promised: see src/docker.ts's allowlist, which refuses
 * any subcommand that could change something.
 *
 * Nothing is written, no container is created or executed, and nothing leaves
 * your machine. `--no-docker` skips the daemon entirely if you would rather it
 * did not look.
 */
import { createRequire } from 'module';
import path from 'path';

import { checkMountAllowlist, defaultAllowlistPath } from './checks/mount-allowlist.js';
import { checkNonRoot } from './checks/non-root.js';
import { checkEgressExposure } from './checks/egress.js';
import { checkReleaseAgeGate, checkInstallScriptAllowlist } from './checks/supply-chain.js';
import { checkAgentImagePin } from './checks/agent-image.js';
import { checkEgressLockdownWiring } from './checks/egress-lockdown.js';
import { checkRuntimeClass } from './checks/runtime-class.js';
import { detectIsthmus, checkKernelLiveness } from './checks/isthmus-mode.js';
import { RealDockerRunner, type DockerRunner } from './docker.js';
import { compareReports, formatComparisonHuman, loadBaseline } from './compare.js';
import { formatReportHuman, type CheckResult, type MigrationState, type ScanReport } from './report.js';

const toolVersion: string = (() => {
  try {
    return (createRequire(import.meta.url)('../package.json') as { version: string }).version;
  } catch {
    return 'unknown';
  }
})();

/** Reads a flag written either as `--name=value` or `--name value`. */
function flagValue(args: string[], name: string): string | undefined {
  const inline = args.find((a) => a.startsWith(`--${name}=`));
  if (inline) return inline.slice(`--${name}=`.length);
  const idx = args.indexOf(`--${name}`);
  if (idx !== -1 && idx + 1 < args.length && !args[idx + 1].startsWith('-')) return args[idx + 1];
  return undefined;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    printUsage();
    return;
  }
  if (args.includes('--version') || args.includes('-v')) {
    process.stdout.write(`${toolVersion}\n`);
    return;
  }

  const json = args.includes('--json');
  const noDocker = args.includes('--no-docker');
  const comparePath = flagValue(args, 'compare');
  const allowlistPath = flagValue(args, 'allowlist') ?? defaultAllowlistPath();

  // Any value consumed by a `--name value` flag is not the positional target.
  const consumed = new Set([comparePath, args.includes('--allowlist') ? allowlistPath : undefined]);
  const positional = args.find((a) => !a.startsWith('-') && !consumed.has(a));
  const target = path.resolve(positional ?? process.cwd());

  // A runner that reports itself unavailable makes every Docker-dependent
  // check report `skip` through its own normal path, so --no-docker needs no
  // special-casing anywhere else.
  const docker: DockerRunner = noDocker
    ? { available: () => false, run: () => ({ ok: false, stdout: '', stderr: '--no-docker' }) }
    : new RealDockerRunner();

  const isthmusDetected = detectIsthmus(target);

  // Probed first, not last: whether the kernel is answering decides what the
  // other checks can honestly claim about who enforces them, so it cannot be
  // an afterthought appended to the list.
  const kernelCheck = isthmusDetected ? await checkKernelLiveness(target) : null;
  const kernelEnforcing = kernelCheck?.level === 'pass';

  const migrationState: MigrationState = !isthmusDetected
    ? 'not-migrated'
    : kernelEnforcing
      ? 'migrated-enforcing'
      : 'migrated-not-enforcing';

  const checks: CheckResult[] = [
    checkMountAllowlist(allowlistPath, kernelEnforcing),
    checkNonRoot(target),
    checkEgressExposure(kernelEnforcing),
    checkEgressLockdownWiring(target, docker),
    checkRuntimeClass(docker),
    checkReleaseAgeGate(target),
    checkInstallScriptAllowlist(target),
    checkAgentImagePin(target, docker),
  ];
  if (kernelCheck) checks.push(kernelCheck);

  const report: ScanReport = {
    generatedAt: new Date().toISOString(),
    toolVersion,
    target,
    isthmusDetected,
    migrationState,
    checks,
  };

  if (comparePath) {
    let comparison;
    try {
      comparison = compareReports(loadBaseline(comparePath), report);
    } catch (err) {
      process.stderr.write(
        `isthmus-scan: could not read baseline ${comparePath}: ${err instanceof Error ? err.message : String(err)}\n`,
      );
      process.exitCode = 2;
      return;
    }
    process.stdout.write(
      (json ? JSON.stringify({ report, comparison }, null, 2) : formatComparisonHuman(comparison)) + '\n',
    );
  } else {
    process.stdout.write((json ? JSON.stringify(report, null, 2) : formatReportHuman(report)) + '\n');
  }

  // Unchanged rule, deliberately: only a real FAIL is non-zero, so an INFO, a
  // SKIP, a clean pass — or a comparison, however it reads — stays safe to
  // wire into a script or CI check.
  process.exitCode = checks.some((c) => c.level === 'fail') ? 1 : 0;
}

function printUsage(): void {
  process.stdout.write(
    [
      'Usage: isthmus-scan [path] [--json] [--allowlist=<path>] [--compare=<baseline.json>] [--no-docker]',
      '',
      '  path                  NanoClaw checkout to scan (default: current directory)',
      '  --json                machine-readable output',
      "  --allowlist=<path>    override the mount-allowlist.json location (default: ~/.config/nanoclaw/mount-allowlist.json)",
      '  --compare=<file>      diff this scan against a baseline written earlier with --json',
      '  --no-docker           skip every check that asks the Docker daemon',
      '  --version             print the version and exit',
      '',
      'Read-only. Nothing is written, no container is created or executed, nothing',
      'leaves your machine. Docker is only ever asked to describe what it already',
      'has (info, ps, inspect) — see src/docker.ts for the enforced allowlist.',
      '',
      'Before/after a migration to Isthmus:',
      '  isthmus-scan --json > before.json',
      '  isthmus-scan --compare=before.json',
      '',
      'https://github.com/prathish-ks/isthmus-scan',
      '',
    ].join('\n'),
  );
}

main().catch((err) => {
  process.stderr.write(`isthmus-scan: unexpected error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 2;
});
