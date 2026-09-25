/**
 * Shared result shape every check returns. Modeled on Isthmus's own
 * `nanogo doctor`/`security-check` PASS/WARN/FAIL convention (see
 * https://github.com/prathish-ks/isthmus/blob/main/go-host/internal/securitycheck/securitycheck.go)
 * so the two tools read the same way if you've used either.
 */
export type Level = 'pass' | 'warn' | 'fail' | 'info' | 'skip';

/**
 * Who, if anyone, actually enforces this beyond this scan noticing it once.
 *
 * Replaces v0.1.x's `isthmusEnforced: boolean`, which could not express the
 * common case: a gate NanoClaw enforces perfectly well on its own, with
 * Isthmus nowhere in the picture. Worse, a boolean forced every check to
 * pick a side at authoring time, when for most of them the honest answer
 * depends on what the scan actually found — a digest pin is enforced by
 * Docker, a floating tag is enforced by nobody, and that is the finding.
 *
 * This is deliberately computed per run, not hardcoded per check.
 */
export type Enforcement =
  /** Isthmus's Go kernel re-validates this at the request boundary, continuously. */
  | 'isthmus-kernel'
  /** NanoClaw itself enforces it — at spawn, at install, or via the container runtime. */
  | 'nanoclaw-native'
  /** Nothing enforces it. This scan reading the file is the only check there is. */
  | 'unenforced';

export interface CheckResult {
  name: string;
  level: Level;
  detail: string;
  remediation?: string;
  enforcement: Enforcement;
}

/**
 * How far along a NanoClaw → Isthmus migration this checkout is. A plain
 * boolean "is this Isthmus" reported a half-migrated install — cloned, Go
 * kernel never built or never started — identically to a broken one, which
 * is the least useful moment to be vague.
 */
export type MigrationState =
  /** No go-host/. Plain NanoClaw; every NanoClaw-native check still applies. */
  | 'not-migrated'
  /** go-host/ present, but nothing is answering on the kernel socket yet. */
  | 'migrated-not-enforcing'
  /** The kernel socket answers — config checks are valid AND continuously enforced. */
  | 'migrated-enforcing';

export interface ScanReport {
  generatedAt: string;
  /** isthmus-scan's own version, so a --compare baseline says what produced it. */
  toolVersion: string;
  target: string;
  isthmusDetected: boolean;
  migrationState: MigrationState;
  checks: CheckResult[];
}

const LEVEL_LABEL: Record<Level, string> = {
  pass: 'PASS',
  warn: 'WARN',
  fail: 'FAIL',
  info: 'INFO',
  skip: 'SKIP',
};

const MIGRATION_FOOTER: Record<MigrationState, string> = {
  'not-migrated': '',
  'migrated-not-enforcing':
    "Isthmus is present at this path but its kernel isn't answering, so nothing above is being enforced at the request boundary yet. That's the expected state before the host has started once — the configuration findings above are still accurate either way.",
  'migrated-enforcing':
    'Isthmus detected and its kernel is answering — the checks marked as kernel-enforced above are being actively enforced, not just configured.',
};

export function formatReportHuman(report: ScanReport): string {
  const lines: string[] = [];
  lines.push(`isthmus-scan ${report.toolVersion} — ${report.target}`);
  lines.push(report.generatedAt);
  lines.push('');

  for (const c of report.checks) {
    lines.push(`[${LEVEL_LABEL[c.level]}] ${c.name}`);
    lines.push(`  ${c.detail}`);
    if (c.remediation) lines.push(`  -> ${c.remediation}`);
  }

  const failing = report.checks.filter((c) => c.level === 'fail' || c.level === 'warn');
  lines.push('');
  lines.push(`${failing.length} of ${report.checks.length} checks need attention.`);

  if (failing.length > 0) {
    const byEnforcement = (e: Enforcement) => failing.filter((c) => c.enforcement === e).map((c) => c.name);

    const kernel = byEnforcement('isthmus-kernel');
    const native = byEnforcement('nanoclaw-native');
    const unenforced = byEnforcement('unenforced');

    lines.push('');
    if (kernel.length > 0) {
      lines.push(
        `${kernel.length} of these Isthmus's kernel continuously enforces at the request boundary (not just re-checked by hand): ${kernel.join(', ')}.`,
      );
    }
    if (native.length > 0) {
      lines.push(
        `${native.length} NanoClaw enforces itself once configured — Isthmus doesn't change these, this scan just helps you see them: ${native.join(', ')}.`,
      );
    }
    if (unenforced.length > 0) {
      lines.push(
        `${unenforced.length} nothing is enforcing right now — this scan reading the file is the only check there is: ${unenforced.join(', ')}.`,
      );
    }
  }

  const footer = MIGRATION_FOOTER[report.migrationState];
  if (footer) {
    lines.push('');
    lines.push(footer);
  }

  return lines.join('\n');
}
