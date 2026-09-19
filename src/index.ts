#!/usr/bin/env node
/**
 * isthmus-scan — a free, read-only hardening scanner for NanoClaw installs.
 * https://github.com/prathish-ks/isthmus-scan
 *
 * Every check here is read-only: it opens files that already exist and, for
 * the Isthmus kernel-liveness check, makes one short-timeout local socket
 * connection. Nothing is written, nothing leaves your machine, no network
 * calls beyond that local socket probe.
 */
import path from 'path';

import { checkMountAllowlist, defaultAllowlistPath } from './checks/mount-allowlist.js';
import { checkNonRoot } from './checks/non-root.js';
import { checkEgressExposure } from './checks/egress.js';
import { detectIsthmus, checkKernelLiveness } from './checks/isthmus-mode.js';
import { formatReportHuman, type CheckResult, type ScanReport } from './report.js';

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    printUsage();
    return;
  }

  const json = args.includes('--json');
  const positional = args.find((a) => !a.startsWith('-'));
  const target = path.resolve(positional ?? process.cwd());
  const allowlistFlag = args.find((a) => a.startsWith('--allowlist='));
  const allowlistPath = allowlistFlag ? allowlistFlag.slice('--allowlist='.length) : defaultAllowlistPath();

  const isthmusDetected = detectIsthmus(target);

  const checks: CheckResult[] = [
    checkMountAllowlist(allowlistPath),
    checkNonRoot(target),
    checkEgressExposure(isthmusDetected),
  ];

  if (isthmusDetected) {
    checks.push(await checkKernelLiveness(target));
  }

  const report: ScanReport = {
    generatedAt: new Date().toISOString(),
    target,
    isthmusDetected,
    checks,
  };

  process.stdout.write((json ? JSON.stringify(report, null, 2) : formatReportHuman(report)) + '\n');

  const hasFail = checks.some((c) => c.level === 'fail');
  process.exitCode = hasFail ? 1 : 0;
}

function printUsage(): void {
  process.stdout.write(
    [
      'Usage: isthmus-scan [path] [--json] [--allowlist=<path>]',
      '',
      '  path                  NanoClaw checkout to scan (default: current directory)',
      '  --json                machine-readable output',
      "  --allowlist=<path>    override the mount-allowlist.json location (default: ~/.config/nanoclaw/mount-allowlist.json)",
      '',
      'Read-only. Nothing is written, nothing leaves your machine.',
      'https://github.com/prathish-ks/isthmus-scan',
      '',
    ].join('\n'),
  );
}

main().catch((err) => {
  process.stderr.write(`isthmus-scan: unexpected error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 2;
});
