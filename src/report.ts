/**
 * Shared result shape every check returns. Modeled on Isthmus's own
 * `nanogo doctor`/`security-check` PASS/WARN/FAIL convention (see
 * https://github.com/prathish-ks/isthmus/blob/main/go-host/internal/securitycheck/securitycheck.go)
 * so the two tools read the same way if you've used either.
 */
export type Level = 'pass' | 'warn' | 'fail' | 'info' | 'skip';

export interface CheckResult {
  name: string;
  level: Level;
  detail: string;
  remediation?: string;
  /**
   * true when Isthmus's Go kernel continuously enforces this at the request
   * boundary, not merely something this scan happened to notice once. Only
   * set on checks that are actually wired into the kernel's live dispatch
   * path (mount-allowlist re-validation, egress blocking) — never claimed
   * for a check that's really a NanoClaw-native default or convention.
   */
  isthmusEnforced: boolean;
}

export interface ScanReport {
  generatedAt: string;
  target: string;
  isthmusDetected: boolean;
  checks: CheckResult[];
}

const LEVEL_LABEL: Record<Level, string> = {
  pass: 'PASS',
  warn: 'WARN',
  fail: 'FAIL',
  info: 'INFO',
  skip: 'SKIP',
};

export function formatReportHuman(report: ScanReport): string {
  const lines: string[] = [];
  lines.push(`isthmus-scan — ${report.target}`);
  lines.push(report.generatedAt);
  lines.push('');

  const enforced = report.checks.filter((c) => c.isthmusEnforced);
  const own = report.checks.filter((c) => !c.isthmusEnforced);

  for (const c of report.checks) {
    lines.push(`[${LEVEL_LABEL[c.level]}] ${c.name}`);
    lines.push(`  ${c.detail}`);
    if (c.remediation) lines.push(`  -> ${c.remediation}`);
  }

  const failing = report.checks.filter((c) => c.level === 'fail' || c.level === 'warn');
  lines.push('');
  lines.push(`${failing.length} of ${report.checks.length} checks need attention.`);

  if (failing.length > 0) {
    lines.push('');
    const enforcedFailing = enforced.filter((c) => c.level === 'fail' || c.level === 'warn');
    const ownFailing = own.filter((c) => c.level === 'fail' || c.level === 'warn');
    if (enforcedFailing.length > 0) {
      lines.push(
        `${enforcedFailing.length} of these are things Isthmus's kernel continuously enforces at the request boundary (not just re-checked by hand): ${enforcedFailing.map((c) => c.name).join(', ')}.`,
      );
    }
    if (ownFailing.length > 0) {
      lines.push(
        `${ownFailing.length} are your own configuration either way — Isthmus doesn't change these, this scan just helps you see them: ${ownFailing.map((c) => c.name).join(', ')}.`,
      );
    }
  }

  if (report.isthmusDetected) {
    lines.push('');
    lines.push('Isthmus detected at this path — checks above reflect whether the kernel is actually enforcing, not just installed.');
  }

  return lines.join('\n');
}
