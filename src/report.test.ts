import { describe, expect, it } from 'vitest';

import { formatReportHuman, type ScanReport } from './report.js';

function baseReport(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    generatedAt: '2026-09-20T00:00:00.000Z',
    target: '/tmp/example',
    isthmusDetected: false,
    checks: [],
    ...overrides,
  };
}

describe('formatReportHuman', () => {
  it('renders zero findings cleanly', () => {
    const text = formatReportHuman(baseReport({ checks: [{ name: 'a', level: 'pass', detail: 'fine', isthmusEnforced: false }] }));
    expect(text).toContain('0 of 1 checks need attention');
    expect(text).not.toContain('kernel continuously enforces');
  });

  it('splits failing checks into the Isthmus-enforced and your-own-config buckets', () => {
    const text = formatReportHuman(
      baseReport({
        checks: [
          { name: 'mount-allowlist exposure', level: 'fail', detail: 'bad', isthmusEnforced: true },
          { name: 'non-root containers', level: 'fail', detail: 'bad', isthmusEnforced: false },
        ],
      }),
    );
    expect(text).toContain('1 of these are things Isthmus');
    expect(text).toContain('mount-allowlist exposure');
    expect(text).toContain('1 are your own configuration');
    expect(text).toContain('non-root containers');
  });

  it('does not print the Isthmus-detected footer when Isthmus was not detected', () => {
    const text = formatReportHuman(baseReport());
    expect(text).not.toContain('Isthmus detected at this path');
  });

  it('prints the Isthmus-detected footer when it was', () => {
    const text = formatReportHuman(baseReport({ isthmusDetected: true }));
    expect(text).toContain('Isthmus detected at this path');
  });
});
