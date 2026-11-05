/**
 * Best-effort detection of the running Node environment, for the
 * `reproducibility_context` of a run. A value that cannot be read is
 * left out, and the server records it as not declared.
 */

import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import type { ReproducibilityContext } from "./types.js";

export interface CaptureEnvironmentOptions {
  /** Library name to seed value. Recorded as declared; the caller still
   *  has to apply the seeds. */
  declaredSeeds?: Record<string, string | number>;
  /** List the packages under `node_modules` in the working directory.
   *  Defaults to true. */
  includeDependencies?: boolean;
  /** Read the commit with `git rev-parse HEAD`. Defaults to true. */
  includeGit?: boolean;
  /** Read the container id from `/proc/self/cgroup` on Linux. Defaults
   *  to true. */
  includeContainer?: boolean;
}

const HASH_64 = /^[0-9a-f]{64}$/;
const GIT_SHA = /^([0-9a-f]{40}|[0-9a-f]{64})$/;
const PLATFORM_NAMES: Record<string, string> = { win32: "windows" };
const ARCH_NAMES: Record<string, string> = { x64: "amd64", ia32: "386" };

function packageVersion(dir: string): string | undefined {
  try {
    const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as {
      name?: string;
      version?: string;
    };
    return pkg.name && pkg.version ? `${pkg.name}==${pkg.version}` : undefined;
  } catch {
    return undefined;
  }
}

function packageDirs(root: string): string[] {
  const dirs: string[] = [];
  for (const entry of readdirSync(root)) {
    if (entry.startsWith(".")) continue;
    if (!entry.startsWith("@")) {
      dirs.push(join(root, entry));
      continue;
    }
    for (const scoped of readdirSync(join(root, entry))) {
      dirs.push(join(root, entry, scoped));
    }
  }
  return dirs;
}

function detectDependencies(): string[] | undefined {
  try {
    const pins = packageDirs(join(process.cwd(), "node_modules"))
      .map(packageVersion)
      .filter((pin): pin is string => pin !== undefined);
    pins.sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
    return pins.length > 0 ? pins : undefined;
  } catch {
    return undefined;
  }
}

function detectGitSHA(): string | undefined {
  try {
    const sha = execFileSync("git", ["rev-parse", "HEAD"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 2000,
    })
      .trim()
      .toLowerCase();
    return GIT_SHA.test(sha) ? sha : undefined;
  } catch {
    return undefined;
  }
}

function detectContainerHash(): string | undefined {
  try {
    const text = readFileSync("/proc/self/cgroup", "utf8");
    return text
      .split("\n")
      .flatMap((line) => line.split("/"))
      .map((segment) => segment.trim())
      .find((segment) => HASH_64.test(segment));
  } catch {
    return undefined;
  }
}

/** Auto-detects the running Node environment. */
export function captureEnvironment(
  options: CaptureEnvironmentOptions = {},
): ReproducibilityContext {
  const seeds = Object.entries(options.declaredSeeds ?? {})
    .map(([name, seed]) => `${name}=${seed}`)
    .sort();
  const pinned =
    options.includeDependencies === false ? undefined : detectDependencies();
  const git = options.includeGit === false ? undefined : detectGitSHA();
  const container =
    options.includeContainer === false ? undefined : detectContainerHash();
  const os = PLATFORM_NAMES[process.platform] ?? process.platform;
  const arch = ARCH_NAMES[process.arch] ?? process.arch;

  return {
    declared: true,
    runtime_name: "node",
    runtime_version: process.versions.node,
    platform: `${os}/${arch}`,
    ...(pinned ? { pinned_dependencies: pinned } : {}),
    ...(git ? { git_commit_sha: git } : {}),
    ...(container ? { container_image_hash: container } : {}),
    ...(seeds.length > 0 ? { random_seeds: seeds } : {}),
  };
}
