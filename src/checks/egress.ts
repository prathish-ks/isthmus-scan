/**
 * Informational only, deliberately: this does not probe live firewall
 * rules (that would need root/iptables access and differs by platform,
 * which is more than a trial tool should ask for). It states a structural
 * fact — stock NanoClaw has no built-in mitigation for this attack class —
 * and, when Isthmus is detected, points at the one live check that can
 * actually confirm the firewall rule is active.
 */
import type { CheckResult } from '../report.js';

export function checkEgressExposure(isthmusDetected: boolean): CheckResult {
  const name = 'cloud-metadata / link-local egress exposure';

  if (isthmusDetected) {
    return {
      name,
      level: 'info',
      detail:
        'Isthmus adds a firewall rule blocking agent-container access to cloud-metadata and link-local addresses (e.g. 169.254.169.254) — a standard way a compromised container steals cloud credentials.',
      remediation: 'run `nanogo doctor` to verify the rule is actually active on this machine, not just configured',
      isthmusEnforced: true,
    };
  }

  return {
    name,
    level: 'info',
    detail:
      'stock NanoClaw has no built-in mitigation for agent containers reaching cloud-metadata or link-local addresses (e.g. 169.254.169.254) — a standard way a compromised container steals cloud credentials. This is not a live probe of your firewall; it is a statement about what NanoClaw does and does not ship by default.',
    isthmusEnforced: true,
  };
}
