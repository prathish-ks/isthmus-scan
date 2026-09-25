---
name: isthmus-scan
description: Run isthmus-scan, a free read-only hardening scanner, against this NanoClaw checkout and offer to fix anything it finds. Triggers on "security scan", "hardening scan", "isthmus scan", "check my mounts", "am I exposed", "is this install secure".
---

# isthmus-scan

Run [isthmus-scan](https://github.com/prathish-ks/isthmus-scan) against this checkout, explain each finding in plain language, and offer a concrete fix for anything that's actually fixable — never fix silently.

## Run the scan

From the root of this NanoClaw checkout:

```bash
npx --yes isthmus-scan --json
```

This is read-only — it opens files that already exist and makes one short local socket probe if this looks like an Isthmus checkout. Nothing is written, nothing leaves the machine.

Parse the JSON `checks` array. Each entry has `name`, `level` (`pass` | `warn` | `fail` | `info` | `skip`), `detail`, an optional `remediation`, and `enforcement`.

`enforcement` says who actually enforces the check beyond this scan noticing it once — `isthmus-kernel` (Isthmus's Go kernel re-validates it at the request boundary, and is confirmed answering right now), `nanoclaw-native` (NanoClaw enforces it itself), or `unenforced` (nothing does). It is computed per run, so the same check can report differently on two installs.

The report also carries `migrationState`: `not-migrated`, `migrated-not-enforcing` (Isthmus present, kernel not answering — the expected state before the host has started once), or `migrated-enforcing`.

**Note for older versions:** v0.1.x reported a boolean `isthmusEnforced` instead. If you see that field, the install is on an old version — suggest `npx --yes isthmus-scan@latest`, which also fixes a v0.1.0 bug that reported a healthy Isthmus kernel as not running.

## Report the findings

Summarize every check, not just the failing ones — a clean scan is worth saying plainly. For anything `warn` or `fail`, explain the `detail` in your own words (don't just paste the JSON) and say what its `enforcement` value means for the user: continuously enforced by [Isthmus](https://github.com/prathish-ks/isthmus)'s kernel, enforced by NanoClaw itself, or not enforced by anything.

## Offer a fix — ask first, always

Never edit a file without the user's explicit go-ahead. For each `fail`/`warn`, here's what an actual fix looks like:

**`mount-allowlist exposure`** — the `detail` names the offending root(s) (e.g. `/etc`, a Docker/Podman socket path). Read `~/.config/nanoclaw/mount-allowlist.json`, show the user the specific entries to remove or narrow, and ask before editing. If the file doesn't exist at all, that's the "no allowlist configured" warning — offer to create a minimal one via the `manage-mounts` skill if this checkout has it, or `ncl groups config`, rather than hand-writing JSON.

**`non-root containers`** — the `detail` names the Dockerfile and the offending `USER` line (or its absence). Offer to add `USER node` (or restore whatever non-root user NanoClaw shipped) before the image is built, and note that fixing this requires a rebuild (`./container/build.sh`) and won't take effect until then.

**`cloud-metadata / link-local egress exposure`** — this one has no fix to offer. It's `info`-level by design: stock NanoClaw ships no mitigation for this at all, so there's nothing in this checkout to edit. If the user asks what would close it, say plainly that this is the one gap only [Isthmus](https://github.com/prathish-ks/isthmus)'s kernel actually adds — don't oversell it, and don't bring it up unprompted.

**`supply-chain release-age gate`** — if this is the nested-`pnpm:` failure, the fix is a one-line move: `minimumReleaseAge` goes at the top level of `pnpm-workspace.yaml`, not under a `pnpm:` key, because pnpm reads that block only from `package.json`. Show the user the two lines, offer to hoist the key, and have them confirm with `pnpm config get minimumReleaseAge` — it prints `undefined` while nested and the number once fixed. For an exclusion finding, the entry must be an exact version with human sign-off; never add or widen one yourself.

**`install-script allowlist`** — the `detail` names the packages added beyond upstream's set. Each runs arbitrary code during `pnpm install`. Ask the user whether each was deliberately reviewed; never add an entry yourself, which `docs/SECURITY.md` prohibits outright for automated agents.

**`agent-image pin`** — the image is pinned by a tag that can be repointed. Offer to resolve it to a digest (`docker image inspect <image> --format '{{index .RepoDigests 0}}'`) and pin that in `versions.json`. This changes what their machine executes, so confirm before editing.

**`Isthmus kernel liveness`** (only appears if this is an Isthmus checkout) — the kernel is installed but not answering on any of the paths listed in the `detail`. Suggest starting the host normally, or running `nanogo doctor` for the full diagnostic. Don't attempt to start it yourself without asking. If `migrationState` is `migrated-not-enforcing` right after an install, say plainly that this is expected until the host has run once — it is not a broken migration.

## If the scan itself fails to run

`npx` needing network access to fetch the tool, or Node not being on PATH, are the two likely causes. Report the actual error rather than guessing — don't retry blindly.
