import { describe, expect, it } from 'vitest';

import { formatReportHuman, type CheckResult, type ScanReport } from './report.js';

function check(overrides: Partial<CheckResult> = {}): CheckResult {
  return { name: 'a', level: 'pass', detail: 'fine', enforcement: 'unenforced', ...overrides };
}

function baseReport(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    generatedAt: '2026-09-20T00:00:00.000Z',
    toolVersion: '0.2.0',
    target: '/tmp/example',
    isthmusDetected: false,
    migrationState: 'not-migrated',
    checks: [],
    ...overrides,
  };
}

describe('formatReportHuman', () => {
  it('renders zero findings cleanly', () => {
    const text = formatReportHuman(baseReport({ checks: [check()] }));
    expect(text).toContain('0 of 1 checks need attention');
    expect(text).not.toContain('continuously enforces');
  });

  it('names the tool version, so a pasted report says what produced it', () => {
    expect(formatReportHuman(baseReport())).toContain('isthmus-scan 0.2.0');
  });

  it('buckets failing checks by who actually enforces them', () => {
    const text = formatReportHuman(
      baseReport({
        checks: [
          check({ name: 'mount-allowlist exposure', level: 'fail', enforcement: 'isthmus-kernel' }),
          check({ name: 'install-script allowlist', level: 'warn', enforcement: 'nanoclaw-native' }),
          check({ name: 'agent-image pin', level: 'warn', enforcement: 'unenforced' }),
        ],
      }),
    );
    expect(text).toContain("1 of these Isthmus's kernel continuously enforces");
    expect(text).toContain('mount-allowlist exposure');
    expect(text).toContain('1 NanoClaw enforces itself once configured');
    expect(text).toContain('install-script allowlist');
    expect(text).toContain('1 nothing is enforcing right now');
    expect(text).toContain('agent-image pin');
  });

  it('omits a bucket with nothing in it', () => {
    const text = formatReportHuman(
      baseReport({ checks: [check({ name: 'x', level: 'fail', enforcement: 'unenforced' })] }),
    );
    expect(text).not.toContain('continuously enforces');
    expect(text).not.toContain('NanoClaw enforces itself');
  });

  it('prints no migration footer for a plain NanoClaw checkout', () => {
    const text = formatReportHuman(baseReport());
    expect(text).not.toContain('Isthmus');
  });

  it('distinguishes a half-migrated install from an enforcing one', () => {
    const halfway = formatReportHuman(
      baseReport({ isthmusDetected: true, migrationState: 'migrated-not-enforcing' }),
    );
    expect(halfway).toContain("isn't answering");
    expect(halfway).toContain('expected state before the host has started');

    const enforcing = formatReportHuman(baseReport({ isthmusDetected: true, migrationState: 'migrated-enforcing' }));
    expect(enforcing).toContain('kernel is answering');
    expect(enforcing).not.toContain("isn't answering");
  });
});
