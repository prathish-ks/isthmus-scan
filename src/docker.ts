/**
 * The narrow seam every Docker call in this tool goes through.
 *
 * Modeled on Isthmus's own `doctor.CommandRunner` for the same reason it
 * exists there: tests fake exactly one external dependency (what `docker`
 * prints, what it exits with) instead of needing a real daemon in CI.
 *
 * # Read-only, enforced rather than promised
 *
 * Up to v0.2.0 this tool only opened files, so "read-only" was self-evident
 * from the absence of anything else. Now that it shells `docker`, that claim
 * needs a mechanism: ALLOWED_COMMANDS below is an allowlist of read-only
 * subcommands, checked on every call, and anything else throws. A future edit
 * that reaches for `docker network create` or `docker rm` fails immediately
 * and loudly rather than quietly making the README a lie.
 *
 * Note what is deliberately absent: `docker run`, `docker exec`, `docker
 * create`. Isthmus's own egress check inspects the real DOCKER-USER chain by
 * running a helper container with `--network host --cap-add NET_ADMIN` — by
 * its own comment the single most privileged container that project runs. A
 * free scanner someone points at their machine on a stranger's recommendation
 * must not do that, so this tool reads Docker's own view of the world and
 * stops there.
 */
import { execFileSync } from 'child_process';

/** NanoClaw hardcodes this too (src/container-runtime.ts's CONTAINER_RUNTIME_BIN). */
const RUNTIME_BIN = 'docker';

/**
 * Read-only subcommands only. Each entry is matched as an exact prefix of the
 * argument list, so `network inspect` is permitted while `network create` is
 * not, even though both start with `network`.
 */
const ALLOWED_COMMANDS: string[][] = [
  ['info'],
  ['ps'],
  ['inspect'],
  ['image', 'inspect'],
  ['network', 'inspect'],
  ['network', 'ls'],
  ['version'],
];

export interface DockerResult {
  ok: boolean;
  stdout: string;
  stderr: string;
}

export interface DockerRunner {
  /** True when the binary exists AND the daemon answers. Both, because a binary with a dead daemon fails every call below. */
  available(): boolean;
  run(args: string[]): DockerResult;
}

function assertReadOnly(args: string[]): void {
  const permitted = ALLOWED_COMMANDS.some((cmd) => cmd.every((part, i) => args[i] === part));
  if (!permitted) {
    throw new Error(
      `isthmus-scan refuses to run \`docker ${args.join(' ')}\` — this tool is read-only, and only ${ALLOWED_COMMANDS.map((c) => c.join(' ')).join(', ')} are permitted`,
    );
  }
}

export class RealDockerRunner implements DockerRunner {
  private daemonOk: boolean | undefined;

  available(): boolean {
    // Cached: every check asks, and `docker info` against a dead daemon can
    // sit for a while before failing.
    if (this.daemonOk === undefined) this.daemonOk = this.run(['info', '--format', '{{.ServerVersion}}']).ok;
    return this.daemonOk;
  }

  run(args: string[]): DockerResult {
    assertReadOnly(args);
    try {
      // Array form, no shell — args are fixed by this tool's own callers plus
      // an operator-configured network or image name, never remote input.
      const stdout = execFileSync(RUNTIME_BIN, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        encoding: 'utf-8',
        timeout: 10000,
      });
      return { ok: true, stdout: stdout.trim(), stderr: '' };
    } catch (err) {
      const e = err as { stdout?: string; stderr?: string; message?: string };
      return {
        ok: false,
        stdout: (e.stdout ?? '').trim(),
        stderr: (e.stderr ?? e.message ?? '').trim(),
      };
    }
  }
}

/** A runner that answers from a fixed table. Tests only. */
export class FakeDockerRunner implements DockerRunner {
  readonly calls: string[][] = [];

  constructor(
    private readonly responses: Record<string, DockerResult | undefined>,
    private readonly daemonUp = true,
  ) {}

  available(): boolean {
    return this.daemonUp;
  }

  run(args: string[]): DockerResult {
    assertReadOnly(args);
    this.calls.push(args);
    return this.responses[args.join(' ')] ?? { ok: false, stdout: '', stderr: 'no such fake response' };
  }
}

/** The canonical "Docker isn't usable, say so and move on" shape. */
export const DAEMON_UNREACHABLE_DETAIL =
  'the Docker daemon did not answer, so this check could not look. Not reported as a pass or a failure — nothing was observed either way';
