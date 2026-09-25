/**
 * Diffs a fresh scan against a baseline written earlier — the "run it before
 * installing Isthmus to see your current exposure, and again after to confirm
 * the kernel is actually enforcing" workflow, which both projects' READMEs
 * describe and neither tool could actually perform.
 *
 * What makes the comparison meaningful is that almost every check reads a
 * file that exists at the same path, in the same format, on both plain
 * NanoClaw and Isthmus — the mount allowlist, the Dockerfile, versions.json,
 * pnpm-workspace.yaml, .npmrc. Migrating does not move them. So a level that
 * changes is a real change in posture, and an `enforcement` that changes is
 * the migration doing its job.
 */
import fs from 'fs';

import type { CheckResult, Enforcement, Level, ScanReport } from './report.js';

export interface CheckDelta {
  name: string;
  status: 'added' | 'removed' | 'changed' | 'unchanged';
  beforeLevel?: Level;
  afterLevel?: Level;
  beforeEnforcement?: Enforcement;
  afterEnforcement?: Enforcement;
}

export interface Comparison {
  baselineGeneratedAt: string;
  baselineToolVersion: string;
  baselineMigrationState: string;
  currentMigrationState: string;
  /** False when the baseline predates the `enforcement` field, so those deltas were not comparable. */
  enforcementComparable: boolean;
  deltas: CheckDelta[];
}

/**
 * A baseline written by v0.1.x carries `isthmusEnforced: boolean` and no
 * `enforcement`/`migrationState`. Read it rather than refusing: the whole
 * point of a baseline is that it was taken before the upgrade, so demanding
 * the new shape would break the first comparison anyone tries.
 */
interface LegacyCheck {
  name?: unknown;
  level?: unknown;
  enforcement?: unknown;
  isthmusEnforced?: unknown;
}

interface NormalizedCheck {
  name: string;
  level: Level;
  enforcement: Enforcement;
  /**
   * False when the baseline predates the `enforcement` field. A v0.1.x report
   * simply does not carry this information, so comparing against a value
   * derived from its boolean would report every check as "changed" the first
   * time anyone upgrades — an artifact of the upgrade, not a change in the
   * install. Level comparison still works; enforcement is skipped and said
   * to be skipped.
   */
  hasEnforcement: boolean;
}

function normalizeCheck(raw: LegacyCheck): NormalizedCheck | null {
  if (typeof raw?.name !== 'string' || typeof raw?.level !== 'string') return null;
  if (typeof raw.enforcement === 'string') {
    return {
      name: raw.name,
      level: raw.level as Level,
      enforcement: raw.enforcement as Enforcement,
      hasEnforcement: true,
    };
  }
  // v0.1.x's boolean only ever distinguished "Isthmus enforces this" from
  // everything else, so false collapses to unenforced. Kept for display, but
  // never treated as comparable.
  const enforcement: Enforcement =
    typeof raw.isthmusEnforced === 'boolean' && raw.isthmusEnforced ? 'isthmus-kernel' : 'unenforced';
  return { name: raw.name, level: raw.level as Level, enforcement, hasEnforcement: false };
}

export function loadBaseline(file: string): ScanReport {
  const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!parsed || !Array.isArray(parsed.checks)) {
    throw new Error(`${file} is not an isthmus-scan JSON report (no checks array)`);
  }
  return parsed as ScanReport;
}

export function compareReports(baseline: ScanReport, current: ScanReport): Comparison {
  const before = new Map<string, NormalizedCheck>();
  for (const raw of baseline.checks ?? []) {
    const normalized = normalizeCheck(raw as LegacyCheck);
    if (normalized) before.set(normalized.name, normalized);
  }

  const deltas: CheckDelta[] = [];

  for (const check of current.checks) {
    const prior = before.get(check.name);
    if (!prior) {
      deltas.push({ name: check.name, status: 'added', afterLevel: check.level, afterEnforcement: check.enforcement });
      continue;
    }
    before.delete(check.name);
    const enforcementChanged = prior.hasEnforcement && prior.enforcement !== check.enforcement;
    const changed = prior.level !== check.level || enforcementChanged;
    deltas.push({
      name: check.name,
      status: changed ? 'changed' : 'unchanged',
      beforeLevel: prior.level,
      afterLevel: check.level,
      // Omitted when the baseline never carried it, so nothing downstream can
      // present a derived value as though the baseline had stated it.
      beforeEnforcement: prior.hasEnforcement ? prior.enforcement : undefined,
      afterEnforcement: check.enforcement,
    });
  }

  // Anything left was in the baseline and is not in this run.
  for (const leftover of before.values()) {
    deltas.push({
      name: leftover.name,
      status: 'removed',
      beforeLevel: leftover.level,
      beforeEnforcement: leftover.enforcement,
    });
  }

  const normalizedBaseline = (baseline.checks ?? [])
    .map((raw) => normalizeCheck(raw as LegacyCheck))
    .filter((c): c is NormalizedCheck => c !== null);

  return {
    baselineGeneratedAt: baseline.generatedAt ?? 'unknown',
    baselineToolVersion: baseline.toolVersion ?? 'pre-0.2.0',
    baselineMigrationState: baseline.migrationState ?? 'unknown',
    currentMigrationState: current.migrationState,
    enforcementComparable: normalizedBaseline.length === 0 || normalizedBaseline.every((c) => c.hasEnforcement),
    deltas,
  };
}

const ARROW = '->';

export function formatComparisonHuman(comparison: Comparison): string {
  const lines: string[] = [];
  lines.push(
    `compared against a baseline from ${comparison.baselineGeneratedAt} (isthmus-scan ${comparison.baselineToolVersion})`,
  );
  if (comparison.baselineMigrationState !== comparison.currentMigrationState) {
    lines.push(`migration state: ${comparison.baselineMigrationState} ${ARROW} ${comparison.currentMigrationState}`);
  }
  if (!comparison.enforcementComparable) {
    lines.push(
      'note: this baseline predates the `enforcement` field, so only levels were compared — who enforces each check is reported fresh below, not as a change.',
    );
  }
  lines.push('');

  const changed = comparison.deltas.filter((d) => d.status === 'changed');
  const added = comparison.deltas.filter((d) => d.status === 'added');
  const removed = comparison.deltas.filter((d) => d.status === 'removed');
  const unchanged = comparison.deltas.filter((d) => d.status === 'unchanged');

  for (const d of changed) {
    const bits: string[] = [];
    if (d.beforeLevel !== d.afterLevel) bits.push(`${d.beforeLevel?.toUpperCase()} ${ARROW} ${d.afterLevel?.toUpperCase()}`);
    if (d.beforeEnforcement !== undefined && d.beforeEnforcement !== d.afterEnforcement) {
      bits.push(`enforced by ${d.beforeEnforcement} ${ARROW} ${d.afterEnforcement}`);
    }
    lines.push(`[CHANGED] ${d.name}: ${bits.join('; ')}`);
  }
  for (const d of added) {
    lines.push(`[NEW]     ${d.name}: ${d.afterLevel?.toUpperCase()} (not in the baseline)`);
  }
  for (const d of removed) {
    lines.push(`[GONE]    ${d.name}: was ${d.beforeLevel?.toUpperCase()}, not run this time`);
  }

  if (changed.length === 0 && added.length === 0 && removed.length === 0) {
    lines.push('No change against the baseline.');
  }
  lines.push('');
  lines.push(
    `${changed.length} changed, ${added.length} new, ${removed.length} gone, ${unchanged.length} unchanged.`,
  );

  return lines.join('\n');
}
