/**
 * Audits the two pnpm supply-chain defenses NanoClaw documents in
 * docs/SECURITY.md §"Supply Chain Security (pnpm)": the release-age gate and
 * the install-script allowlist.
 *
 * The release-age check exists because of a real, upstream-discovered bug,
 * not a hypothetical. From upstream NanoClaw's own pnpm-workspace.yaml:
 *
 *   > Top-level, NOT nested under a `pnpm:` key: pnpm reads a `pnpm:` config
 *   > block only from package.json. Nested here in pnpm-workspace.yaml the
 *   > setting is silently ignored (`pnpm config get minimumReleaseAge`
 *   > returns undefined with the nested form, 4320 once hoisted), so the
 *   > supply-chain release-age gate was a no-op.
 *
 * A 3-day gate against typosquatting and compromised maintainer accounts,
 * present in the file, reviewed, documented — and doing nothing. That is the
 * exact shape this whole tool exists to catch, so the check reports the
 * nested form as a FAIL rather than reading the number and calling it
 * configured.
 *
 * Both checks read files and nothing else. No Docker, no network.
 */
import fs from 'fs';
import path from 'path';

import type { CheckResult, Enforcement } from '../report.js';
import { findKey, mappingUnder, readYamlLite, sequenceUnder, type YamlLiteResult } from '../yaml-lite.js';

/** docs/SECURITY.md's documented threshold: 4320 minutes = 3 days. */
const EXPECTED_RELEASE_AGE_MINUTES = 4320;

/**
 * The packages upstream NanoClaw permits to run install scripts. Derived from
 * upstream's pnpm-workspace.yaml, NOT from docs/SECURITY.md's prose, which
 * also lists better-sqlite3 — neither upstream's nor Isthmus's actual config
 * carries it, so the prose over-states and must not be the source of truth.
 */
const UPSTREAM_BUILT_DEPENDENCIES = ['esbuild', 'protobufjs', 'sharp'];

/** A version with any range/wildcard character is not the exact pin the docs require. */
const INEXACT_VERSION = /[\^~*x><= |]/i;

function loadWorkspaceYaml(target: string): { result: YamlLiteResult; path: string } | null {
  const file = path.join(target, 'pnpm-workspace.yaml');
  try {
    return { result: readYamlLite(fs.readFileSync(file, 'utf8')), path: file };
  } catch {
    return null;
  }
}

export function checkReleaseAgeGate(target: string): CheckResult {
  const name = 'supply-chain release-age gate';
  const loaded = loadWorkspaceYaml(target);

  if (!loaded) {
    return {
      name,
      level: 'skip',
      detail: `no pnpm-workspace.yaml under ${target} — is this a NanoClaw checkout?`,
      enforcement: 'unenforced',
    };
  }

  const { result, path: file } = loaded;
  if (result.unparseable) {
    return {
      name,
      level: 'warn',
      detail: `could not read ${file} confidently (${result.unparseable}) — not reporting this gate as absent, because this reader gave up rather than proving anything`,
      remediation: 'check the gate by hand: `pnpm config get minimumReleaseAge` should print a number, not undefined',
      enforcement: 'unenforced',
    };
  }

  const found = findKey(result, 'minimumReleaseAge');

  if (found.length === 0) {
    return {
      name,
      level: 'warn',
      detail: `${file} sets no minimumReleaseAge — pnpm will resolve a package version the moment it is published, with no cooling-off window. Most malicious publishes are caught and pulled within 72 hours.`,
      remediation: `add a top-level \`minimumReleaseAge: ${EXPECTED_RELEASE_AGE_MINUTES}\` (3 days) to ${file}`,
      enforcement: 'unenforced',
    };
  }

  // The headline case. Nested under anything (`pnpm:` in practice) means pnpm
  // never reads it, so the value being correct is irrelevant.
  const nested = found.filter((e) => e.path.length > 0);
  const topLevel = found.filter((e) => e.path.length === 0);

  if (topLevel.length === 0 && nested.length > 0) {
    const e = nested[0];
    return {
      name,
      level: 'fail',
      detail: `${file} sets minimumReleaseAge: ${e.value} but nests it under \`${e.path.join('.')}:\` (line ${e.line}). pnpm reads a \`pnpm:\` config block only from package.json — nested in pnpm-workspace.yaml the setting is silently ignored, so the release-age gate is a no-op. The value looks right and does nothing.`,
      remediation: `move minimumReleaseAge to the top level of ${file} (column 0, not under \`${e.path.join('.')}:\`), then confirm with \`pnpm config get minimumReleaseAge\` — it prints undefined while nested`,
      enforcement: 'unenforced',
    };
  }

  const value = Number(topLevel[0].value);
  if (!Number.isFinite(value)) {
    return {
      name,
      level: 'warn',
      detail: `${file}'s top-level minimumReleaseAge is "${topLevel[0].value}", which is not a number of minutes`,
      remediation: `set it to ${EXPECTED_RELEASE_AGE_MINUTES} (3 days), the value docs/SECURITY.md documents`,
      enforcement: 'unenforced',
    };
  }

  const notes: string[] = [];
  let level: CheckResult['level'] = 'pass';
  let enforcement: Enforcement = 'nanoclaw-native';

  if (value < EXPECTED_RELEASE_AGE_MINUTES) {
    level = 'warn';
    notes.push(
      `the window is ${value} minutes, below the ${EXPECTED_RELEASE_AGE_MINUTES} (3 days) docs/SECURITY.md documents`,
    );
  }

  // A stray nested copy alongside a live top-level one is inert, but it is
  // also exactly what someone reads and trusts. Worth naming.
  if (nested.length > 0) {
    if (level === 'pass') level = 'warn';
    notes.push(
      `a second, inert copy is nested under \`${nested[0].path.join('.')}:\` (line ${nested[0].line}) — pnpm ignores it, but a reader won't`,
    );
  }

  // minimumReleaseAgeExclude: every entry is a hole in the gate.
  for (const excludeEntry of findKey(result, 'minimumReleaseAgeExclude')) {
    for (const excluded of mappingUnder(result, excludeEntry)) {
      if (INEXACT_VERSION.test(excluded.value) || excluded.value === '') {
        level = 'fail';
        notes.push(
          `${excluded.key} is excluded from the gate with "${excluded.value}" — docs/SECURITY.md requires an exact version, never a range or wildcard`,
        );
      } else {
        if (level === 'pass') level = 'warn';
        notes.push(
          `${excluded.key}@${excluded.value} is excluded from the gate — intended to be rare, human-approved, and removed once the version ages past the threshold`,
        );
      }
    }
  }

  // .npmrc's minReleaseAge is the documented defense-in-depth fallback for
  // when npm is invoked directly, bypassing pnpm's config entirely.
  const npmrc = path.join(target, '.npmrc');
  let npmrcHasFallback = false;
  try {
    npmrcHasFallback = /^\s*minReleaseAge\s*=/m.test(fs.readFileSync(npmrc, 'utf8'));
  } catch {
    // Absent .npmrc is itself the missing fallback.
  }
  if (!npmrcHasFallback) {
    if (level === 'pass') level = 'warn';
    notes.push(
      `.npmrc carries no minReleaseAge fallback — if npm is ever invoked directly instead of pnpm, nothing applies a cooling-off window`,
    );
  }

  if (level === 'pass') {
    return {
      name,
      level: 'pass',
      detail: `${file} sets a top-level minimumReleaseAge of ${value} minutes (${Math.round(value / 1440)} days) where pnpm actually reads it, with a .npmrc fallback and no exclusions`,
      enforcement,
    };
  }

  if (level === 'fail') enforcement = 'unenforced';

  return {
    name,
    level,
    detail: `${file}'s release-age gate is live (top-level minimumReleaseAge: ${value}), with caveats:\n    ${notes.join('\n    ')}`,
    remediation:
      'narrow or remove the exclusions, restore the .npmrc fallback, and keep the window at or above 4320 minutes — see docs/SECURITY.md §"Supply Chain Security (pnpm)"',
    enforcement,
  };
}

export function checkInstallScriptAllowlist(target: string): CheckResult {
  const name = 'install-script allowlist';
  const loaded = loadWorkspaceYaml(target);

  if (!loaded) {
    return {
      name,
      level: 'skip',
      detail: `no pnpm-workspace.yaml under ${target} — is this a NanoClaw checkout?`,
      enforcement: 'unenforced',
    };
  }

  const { result, path: file } = loaded;
  if (result.unparseable) {
    return {
      name,
      level: 'warn',
      detail: `could not read ${file} confidently (${result.unparseable}) — not reporting the allowlist as empty, because this reader gave up rather than proving anything`,
      remediation: 'check `onlyBuiltDependencies` in that file by hand',
      enforcement: 'unenforced',
    };
  }

  const found = findKey(result, 'onlyBuiltDependencies');
  if (found.length === 0) {
    return {
      name,
      level: 'warn',
      detail: `${file} sets no onlyBuiltDependencies — without it, pnpm's own default decides which packages may execute install and postinstall scripts, and a build script runs arbitrary code as the installing user`,
      remediation: `add an onlyBuiltDependencies list naming only the packages that genuinely need to build (upstream's set is ${UPSTREAM_BUILT_DEPENDENCIES.join(', ')})`,
      enforcement: 'unenforced',
    };
  }

  const allowed = found.flatMap((entry) => sequenceUnder(result, entry)).filter((v) => v !== '');
  const extras = allowed.filter((pkg) => !UPSTREAM_BUILT_DEPENDENCIES.includes(pkg));

  if (extras.length > 0) {
    return {
      name,
      level: 'warn',
      detail: `${file} permits install scripts for ${allowed.length} package(s), ${extras.length} beyond upstream NanoClaw's set: ${extras.join(', ')}. Each one executes arbitrary code with the installing user's permissions during \`pnpm install\`.`,
      remediation:
        'confirm each addition was deliberately reviewed and approved by a human — docs/SECURITY.md requires that, and an agent must never add one on its own',
      enforcement: 'nanoclaw-native',
    };
  }

  return {
    name,
    level: 'pass',
    detail: `${file} permits install scripts only for upstream NanoClaw's own set (${allowed.join(', ') || 'none'}) — no locally added build scripts`,
    enforcement: 'nanoclaw-native',
  };
}
