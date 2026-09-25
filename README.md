# isthmus-scan

Run one command, find out what your NanoClaw agents can actually reach on your machine — not what you assumed they could reach.

```bash
npx isthmus-scan /path/to/your/nanoclaw
```

Free, read-only, no signup, nothing leaves your machine. The whole tool is a few hundred lines across `src/`, one file per check — short enough to read before you run it, which is the point for something making claims about your machine's security.

Most checks just open files. The rest ask your local Docker daemon to describe what it already has (`docker info`, `ps`, `inspect`) — because that is the only way to tell "egress lockdown is configured" apart from "egress lockdown is happening". That read-only boundary is **enforced, not just promised**: [`src/docker.ts`](src/docker.ts) holds an allowlist of read-only subcommands and throws on anything else, so no edit to this tool can quietly start creating networks or running containers. Nothing is ever built, pulled, created or executed, and `--no-docker` skips the daemon entirely.

## What it checks

NanoClaw agents run in containers, but a handful of settings decide how much of your real machine they can touch if one gets compromised or prompt-injected. `isthmus-scan` checks eight of them:

- **Mount-allowlist exposure** — does your `mount-allowlist.json` grant access to a whole system directory, or the Docker/Podman socket itself? A compromised agent that reaches the Docker socket can control *every* container on the machine, not just its own — this is the same bug class as [CVE-2026-27002](https://github.com/openclaw/openclaw/security/advisories/GHSA-w235-x559-36mg) (CVSS 9.8) in a sibling project. This file is the only gate: on NanoClaw v2.4.0 the spec validator still permits the `allowlisted-extra` mount class unconditionally, so nothing re-checks it. Filed upstream as [nanocoai/nanoclaw#3680](https://github.com/nanocoai/nanoclaw/pull/3680).
- **Supply-chain release-age gate** — is `minimumReleaseAge` where pnpm actually reads it? Nested under a `pnpm:` key in `pnpm-workspace.yaml` the setting is **silently ignored**, so a 3-day gate against typosquatting and compromised maintainer accounts reads as configured and does nothing. Upstream NanoClaw hit this and fixed it by hoisting the key; forks on an older base still carry the broken shape. Also flags gate exclusions and a missing `.npmrc` fallback.
- **Install-script allowlist** — `onlyBuiltDependencies` decides which packages may execute install and postinstall scripts, which run arbitrary code as the installing user. Flags anything added beyond upstream's own set.
- **Agent-image pin** — is `versions.json`'s `agent-image` pinned by digest, or a floating tag? Upstream calls that file "the one file that decides what other people's machines execute". A tag can be repointed at different bytes with nothing in your checkout changing.
- **Egress-lockdown wiring** — if `NANOCLAW_EGRESS_LOCKDOWN=true`, are your agent containers *actually* on the isolated network? This is the one check that needs to look at reality rather than config. Inside Isthmus, lockdown silently stopped reaching containers for an entire release cycle: the network was created and healed on a timer, so `docker network ls` looked perfect, while every agent sat on the default bridge with open egress. Also catches a network that exists but wasn't created `--internal` (correct by name, open in fact) and a conflicting `NANOCLAW_KERNEL_DOCKER_NETWORK`.
- **Container runtime class** — whether agent containers get a hardened runtime (gVisor, Kata, Sysbox) or share the host kernel. Reports; never demands. "No hardened runtime available" is a **pass**, because that's the expected default for a personal install and neither project claims otherwise.
- **Non-root containers** — confirms your agent image hasn't been changed to run as root. (This is NanoClaw's own default — the check exists to catch a local override, not to take credit for it.)
- **Cloud-metadata / link-local egress exposure** — informational: stock NanoClaw ships no mitigation against agent containers reaching cloud-metadata endpoints (e.g. `169.254.169.254`), a standard way a compromised container steals cloud credentials.

If it's an [Isthmus](https://github.com/prathish-ks/isthmus) checkout, it adds a ninth check — **kernel liveness** — confirming the Go trust-kernel is actually running and enforcing, not just installed.

Clean scan? Now you know for sure instead of assuming. Something flagged? You get exactly what and where, plus a remediation line.

## Usage

```bash
npx isthmus-scan                      # scan the current directory
npx isthmus-scan /path/to/nanoclaw    # scan a specific checkout
npx isthmus-scan --json               # machine-readable output
npx isthmus-scan --allowlist=<path>   # override the mount-allowlist location
npx isthmus-scan --compare=before.json # diff against a baseline taken earlier
npx isthmus-scan --no-docker          # skip every check that asks the daemon
```

A check that needs Docker reports `SKIP` when the daemon isn't answering — never
a pass, never a failure. Nothing was observed, so nothing is claimed.

### Before and after a migration

Every check except kernel liveness reads a file that sits at the same path, in
the same format, on both plain NanoClaw and Isthmus — the mount allowlist, the
Dockerfile, `versions.json`, `pnpm-workspace.yaml`, `.npmrc`. Migrating does not
move them, so the two scans are directly comparable:

```bash
npx isthmus-scan --json > before.json   # on plain NanoClaw
# ... migrate to Isthmus ...
npx isthmus-scan --compare=before.json  # what changed, and what now enforces it
```

A level that changed is a real change in posture. An `enforcement` that changed
is the migration doing its job. Baselines written by v0.1.x still work — they
predate the `enforcement` field, so only levels are compared, and the report
says so rather than inventing changes.

Prefer to run straight from source instead of the npm registry? `npx github:prathish-ks/isthmus-scan` works the same way, and `npx github:prathish-ks/isthmus-scan#v0.1.0` pins an exact tagged version.

Exit code is non-zero only if something actually failed — an `INFO` or a clean pass never fails the exit code, so this is safe to wire into a script or CI check.

## Using it as a Claude Code skill

If you use Claude Code with your NanoClaw checkout, copy `.claude/skills/isthmus-scan/` from this repo into your own checkout's `.claude/skills/`:

```bash
curl -sL https://github.com/prathish-ks/isthmus-scan/archive/refs/heads/main.tar.gz | \
  tar -xz --strip-components=3 -C /path/to/your/nanoclaw/.claude/skills/isthmus-scan \
  isthmus-scan-main/.claude/skills/isthmus-scan
```

(Or just download the folder from GitHub.) Then ask your agent to run the scan — it reads the same JSON output as the CLI, explains each finding, and offers to fix what's actually fixable (never silently).

## What this is not

This is not a claim that installing anything fixes everything it finds. Every
finding carries an `enforcement` field saying who, if anyone, actually enforces
it beyond this scan noticing it once:

- `isthmus-kernel` — [Isthmus](https://github.com/prathish-ks/isthmus)'s Go kernel re-validates it at the request boundary, continuously. Only ever reported when the kernel is actually answering, not merely installed.
- `nanoclaw-native` — NanoClaw enforces it itself, at spawn, at install, or via the container runtime. Isthmus doesn't change these; this scan just helps you see them.
- `unenforced` — nothing enforces it. This scan reading the file is the only check there is.

That last value is the interesting one, and it is computed per run, not
hardcoded: a digest-pinned image is enforced by Docker, a floating tag is
enforced by nobody, and a release-age gate nested where pnpm never reads it is
enforced by nobody either. Which one you get *is* the finding.

This also isn't a full security audit. It's a quick, honest, standalone check — same spirit as `nanogo doctor`/`security-check` in Isthmus, but runnable against any NanoClaw install with nothing but Node, which you already have if you're running NanoClaw at all.

It also doesn't inspect your firewall. Isthmus's own egress check reads the real
`DOCKER-USER` chain, which needs a helper container run with `--network host
--cap-add NET_ADMIN` — by that project's own description the most privileged
container it runs. A scanner you point at your machine on a stranger's
recommendation shouldn't do that, so this one reads Docker's own view and stops
there. The cloud-metadata check stays informational for exactly that reason.

## Why this exists

Building [Isthmus](https://github.com/prathish-ks/isthmus) — a small Go trust-kernel that mediates NanoClaw's privileged host decisions — involved finding a couple of real gaps in NanoClaw's own mount validation along the way. This tool is the useful, standalone part of that research: something anyone running NanoClaw can run today, whether or not they ever install the kernel.

## License

MIT
