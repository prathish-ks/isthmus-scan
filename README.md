# isthmus-scan

Run one command, find out what your NanoClaw agents can actually reach on your machine — not what you assumed they could reach.

```bash
npx isthmus-scan /path/to/your/nanoclaw
```

Free, read-only, no signup, nothing leaves your machine. The whole tool is a few hundred lines across `src/`, one file per check — short enough to read before you run it, which is the point for something making claims about your machine's security.

## What it checks

NanoClaw agents run in containers, but a handful of settings decide how much of your real machine they can touch if one gets compromised or prompt-injected. `isthmus-scan` checks three of them:

- **Mount-allowlist exposure** — does your `mount-allowlist.json` grant access to a whole system directory, or the Docker/Podman socket itself? A compromised agent that reaches the Docker socket can control *every* container on the machine, not just its own — this is the same bug class as [CVE-2026-27002](https://github.com/openclaw/openclaw/security/advisories/GHSA-w235-x559-36mg) (CVSS 9.8) in a sibling project, and the specific NanoClaw gap this check is built from is filed upstream as [nanocoai/nanoclaw#3680](https://github.com/nanocoai/nanoclaw/pull/3680).
- **Non-root containers** — confirms your agent image hasn't been changed to run as root. (This is NanoClaw's own default — the check exists to catch a local override, not to take credit for it.)
- **Cloud-metadata / link-local egress exposure** — informational: stock NanoClaw ships no mitigation against agent containers reaching cloud-metadata endpoints (e.g. `169.254.169.254`), a standard way a compromised container steals cloud credentials.

If it's an [Isthmus](https://github.com/prathish-ks/isthmus) checkout, it adds a fourth check — **kernel liveness** — confirming the Go trust-kernel is actually running and enforcing, not just installed.

Clean scan? Now you know for sure instead of assuming. Something flagged? You get exactly what and where, plus a remediation line.

## Usage

```bash
npx isthmus-scan                    # scan the current directory
npx isthmus-scan /path/to/nanoclaw  # scan a specific checkout
npx isthmus-scan --json             # machine-readable output
npx isthmus-scan --allowlist=<path> # override the mount-allowlist location
```

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

This is not a claim that installing anything fixes everything it finds. Two of the checks above — mount-allowlist and egress — are things [Isthmus](https://github.com/prathish-ks/isthmus)'s Go kernel continuously enforces at the request boundary if you run it; the non-root check is just confirming a NanoClaw default hasn't drifted, and Isthmus doesn't change that either way. The report says which is which.

This also isn't a full security audit. It's a quick, honest, standalone check — same spirit as `nanogo doctor`/`security-check` in Isthmus, but runnable against any NanoClaw install with nothing but Node, which you already have if you're running NanoClaw at all.

## Why this exists

Building [Isthmus](https://github.com/prathish-ks/isthmus) — a small Go trust-kernel that mediates NanoClaw's privileged host decisions — involved finding a couple of real gaps in NanoClaw's own mount validation along the way. This tool is the useful, standalone part of that research: something anyone running NanoClaw can run today, whether or not they ever install the kernel.

## License

MIT
