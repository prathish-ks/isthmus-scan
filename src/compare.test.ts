import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { compareReports, formatComparisonHuman, loadBaseline } from './compare.js';
import type { CheckResult, ScanReport } from './report.js';

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'isthmus-scan-compare-test-'));
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function check(overrides: Partial<CheckResult> = {}): CheckResult {
  return { name: 'a', level: 'pass', detail: 'd', enforcement: 'unenforced', ...overrides };
}

function report(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    generatedAt: '2026-09-25T00:00:00.000Z',
    toolVersion: '0.2.0',
    target: '/tmp/x',
    isthmusDetected: false,
    migrationState: 'not-migrated',
    checks: [],
    ...overrides,
  };
}

describe('compareReports', () => {
  it('reports an unchanged check as unchanged', () => {
    const c = [check({ name: 'mount-allowlist exposure' })];
    const d = compareReports(report({ checks: c }), report({ checks: c }));
    expect(d.deltas).toEqual([
      expect.objectContaining({ name: 'mount-allowlist exposure', status: 'unchanged' }),
    ]);
  });

  it('detects a level change', () => {
    const before = report({ checks: [check({ name: 'x', level: 'fail' })] });
    const after = report({ checks: [check({ name: 'x', level: 'pass' })] });
    expect(compareReports(before, after).deltas[0]).toMatchObject({
      status: 'changed',
      beforeLevel: 'fail',
      afterLevel: 'pass',
    });
  });

  it('marks a modern baseline as enforcement-comparable', () => {
    const c = [check({ name: 'x' })];
    expect(compareReports(report({ checks: c }), report({ checks: c })).enforcementComparable).toBe(true);
  });

  it('detects an enforcement change with no level change — the migration signal', () => {
    const before = report({ checks: [check({ name: 'x', enforcement: 'nanoclaw-native' })] });
    const after = report({
      migrationState: 'migrated-enforcing',
      checks: [check({ name: 'x', enforcement: 'isthmus-kernel' })],
    });
    expect(compareReports(before, after).deltas[0]).toMatchObject({
      status: 'changed',
      beforeLevel: 'pass',
      afterLevel: 'pass',
      beforeEnforcement: 'nanoclaw-native',
      afterEnforcement: 'isthmus-kernel',
    });
  });

  it('marks a check the baseline did not have as added', () => {
    const after = report({ checks: [check({ name: 'Isthmus kernel liveness' })] });
    expect(compareReports(report(), after).deltas[0]).toMatchObject({
      name: 'Isthmus kernel liveness',
      status: 'added',
    });
  });

  it('marks a check that stopped running as removed', () => {
    const before = report({ checks: [check({ name: 'gone', level: 'warn' })] });
    expect(compareReports(before, report()).deltas[0]).toMatchObject({
      name: 'gone',
      status: 'removed',
      beforeLevel: 'warn',
    });
  });

  describe('v0.1.x baselines', () => {
    // A baseline is taken BEFORE the upgrade by definition, so refusing the
    // old shape would break the very first comparison anyone attempts.
    it('reads isthmusEnforced: true as isthmus-kernel', () => {
      const legacy = {
        generatedAt: '2026-09-01T00:00:00.000Z',
        target: '/tmp/x',
        isthmusDetected: true,
        checks: [{ name: 'x', level: 'warn', detail: 'd', isthmusEnforced: true }],
      } as unknown as ScanReport;
      const d = compareReports(legacy, report({ checks: [check({ name: 'x', level: 'warn', enforcement: 'isthmus-kernel' })] }));
      expect(d.deltas[0].status).toBe('unchanged');
      expect(d.baselineToolVersion).toBe('pre-0.2.0');
      expect(d.baselineMigrationState).toBe('unknown');
      expect(d.enforcementComparable).toBe(false);
    });

    it('does not report an enforcement change a v0.1.x baseline never stated', () => {
      // The old boolean cannot distinguish nanoclaw-native from unenforced, so
      // treating its derived value as comparable would mark every check
      // "changed" the first time anyone upgrades.
      const legacy = {
        generatedAt: '2026-09-01T00:00:00.000Z',
        checks: [{ name: 'x', level: 'pass', detail: 'd', isthmusEnforced: false }],
      } as unknown as ScanReport;
      const d = compareReports(legacy, report({ checks: [check({ name: 'x', enforcement: 'nanoclaw-native' })] }));
      expect(d.deltas[0].status).toBe('unchanged');
      expect(d.deltas[0].beforeEnforcement).toBeUndefined();
      expect(d.deltas[0].afterEnforcement).toBe('nanoclaw-native');
    });

    it('still reports a level change against a v0.1.x baseline', () => {
      const legacy = {
        generatedAt: '2026-09-01T00:00:00.000Z',
        checks: [{ name: 'x', level: 'pass', detail: 'd', isthmusEnforced: false }],
      } as unknown as ScanReport;
      const d = compareReports(legacy, report({ checks: [check({ name: 'x', level: 'fail', enforcement: 'unenforced' })] }));
      expect(d.deltas[0]).toMatchObject({ status: 'changed', beforeLevel: 'pass', afterLevel: 'fail' });
    });

    it('says in the human output that enforcement was not compared', () => {
      const legacy = {
        generatedAt: '2026-09-01T00:00:00.000Z',
        checks: [{ name: 'x', level: 'pass', detail: 'd', isthmusEnforced: false }],
      } as unknown as ScanReport;
      const text = formatComparisonHuman(
        compareReports(legacy, report({ checks: [check({ name: 'x', enforcement: 'nanoclaw-native' })] })),
      );
      expect(text).toContain('predates the `enforcement` field');
      expect(text).toContain('No change against the baseline');
    });

    it('reads isthmusEnforced: false as unenforced', () => {
      const legacy = {
        generatedAt: '2026-09-01T00:00:00.000Z',
        checks: [{ name: 'x', level: 'pass', detail: 'd', isthmusEnforced: false }],
      } as unknown as ScanReport;
      expect(compareReports(legacy, report({ checks: [check({ name: 'x' })] })).deltas[0].status).toBe('unchanged');
    });

    it('skips malformed baseline entries instead of crashing', () => {
      const legacy = {
        generatedAt: 'x',
        checks: [{ nope: true }, { name: 'x', level: 'pass' }],
      } as unknown as ScanReport;
      const d = compareReports(legacy, report({ checks: [check({ name: 'x' })] }));
      expect(d.deltas).toHaveLength(1);
      expect(d.deltas[0].status).toBe('unchanged');
    });
  });
});

describe('loadBaseline', () => {
  it('reads a report written with --json', () => {
    const file = path.join(dir, 'before.json');
    fs.writeFileSync(file, JSON.stringify(report({ checks: [check({ name: 'x' })] })));
    expect(loadBaseline(file).checks).toHaveLength(1);
  });

  it('refuses a JSON file that is not a scan report', () => {
    const file = path.join(dir, 'other.json');
    fs.writeFileSync(file, JSON.stringify({ hello: 'world' }));
    expect(() => loadBaseline(file)).toThrow(/not an isthmus-scan JSON report/);
  });

  it('propagates a read failure rather than inventing an empty baseline', () => {
    expect(() => loadBaseline(path.join(dir, 'missing.json'))).toThrow();
  });
});

describe('formatComparisonHuman', () => {
  it('says plainly when nothing changed', () => {
    const c = [check({ name: 'x' })];
    const text = formatComparisonHuman(compareReports(report({ checks: c }), report({ checks: c })));
    expect(text).toContain('No change against the baseline');
  });

  it('shows the migration state transition', () => {
    const before = report({ checks: [check({ name: 'x', enforcement: 'nanoclaw-native' })] });
    const after = report({
      migrationState: 'migrated-enforcing',
      checks: [check({ name: 'x', enforcement: 'isthmus-kernel' })],
    });
    const text = formatComparisonHuman(compareReports(before, after));
    expect(text).toContain('not-migrated -> migrated-enforcing');
    expect(text).toContain('enforced by nanoclaw-native -> isthmus-kernel');
  });

  it('renders a level regression', () => {
    const before = report({ checks: [check({ name: 'x', level: 'pass' })] });
    const after = report({ checks: [check({ name: 'x', level: 'fail' })] });
    expect(formatComparisonHuman(compareReports(before, after))).toContain('PASS -> FAIL');
  });

  it('counts every bucket', () => {
    const before = report({ checks: [check({ name: 'kept' }), check({ name: 'gone' })] });
    const after = report({ checks: [check({ name: 'kept' }), check({ name: 'new' })] });
    expect(formatComparisonHuman(compareReports(before, after))).toContain(
      '0 changed, 1 new, 1 gone, 1 unchanged.',
    );
  });
});
