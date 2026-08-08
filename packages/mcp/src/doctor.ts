/**
 * `ownerswitch-mcp doctor` — a preflight check, run by hand before you ever
 * point an MCP client at the gateway. Every failure line says what to do
 * about it: the goal is that nobody has to ask an agent to debug their own
 * connection (which burns the agent's quota diagnosing infrastructure, not
 * doing the task).
 */
import { randomBytes } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { signDeviceRequest } from "@ownerswitchai/control-plane";
import { ConfigError, loadConfig, type OwnerSwitchMcpConfig, type UpstreamConfig } from "./config.js";
import type { DeviceIdentity } from "./veto-client.js";

export interface DoctorCheck {
  name: string;
  ok: boolean;
  detail: string;
  /** what to do about it — required whenever ok is false */
  fix?: string;
}

export interface DoctorDeps {
  fetchImpl?: typeof fetch;
  spawnImpl?: typeof spawn;
  readFile?: (path: string) => string;
  nodeVersion?: string;
}

const MIN_NODE_MAJOR = 22;

const skipped = (name: string, why: string): DoctorCheck => ({
  name,
  ok: false,
  detail: `skipped — ${why}`,
  fix: "fix the failing check above first, then re-run doctor",
});

export function checkNodeVersion(nodeVersion = process.versions.node): DoctorCheck {
  const major = Number(nodeVersion.split(".")[0]);
  if (major >= MIN_NODE_MAJOR) {
    return { name: "node version", ok: true, detail: `v${nodeVersion} (>= ${MIN_NODE_MAJOR} required)` };
  }
  return {
    name: "node version",
    ok: false,
    detail: `v${nodeVersion} is older than the required ${MIN_NODE_MAJOR}+`,
    fix: `install Node ${MIN_NODE_MAJOR} or newer (e.g. "nvm install ${MIN_NODE_MAJOR}") and re-run`,
  };
}

export function checkConfig(
  argv: string[],
  env: Record<string, string | undefined>,
  readFile?: (path: string) => string,
): { check: DoctorCheck; config?: OwnerSwitchMcpConfig } {
  try {
    const config = readFile === undefined ? loadConfig(argv, env) : loadConfig(argv, env, readFile);
    return {
      check: {
        name: "config",
        ok: true,
        detail:
          `parses — control plane ${config.controlPlaneUrl}, upstream "${config.upstream.command}", ` +
          `${config.policy.rules.length} rule(s), default "${config.policy.defaultDecision}"`,
      },
      config,
    };
  } catch (err) {
    const message = err instanceof ConfigError ? err.message : err instanceof Error ? err.message : String(err);
    return {
      check: {
        name: "config",
        ok: false,
        detail: message,
        fix: "fix the config file (see README's Configuration table) and re-run",
      },
    };
  }
}

export async function checkControlPlane(
  baseUrl: string,
  timeoutMs: number,
  fetchImpl: typeof fetch = fetch,
): Promise<{ check: DoctorCheck; reachable: boolean }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(new URL("/status", baseUrl), { signal: controller.signal });
    if (!res.ok) {
      return {
        reachable: false,
        check: {
          name: "control plane",
          ok: false,
          detail: `${baseUrl} responded HTTP ${res.status}`,
          fix: "check controlPlaneUrl in your config and that the control plane process is healthy",
        },
      };
    }
    const body = (await res.json().catch(() => null)) as { killed?: unknown } | null;
    const killed = body?.killed === true;
    return {
      reachable: true,
      check: {
        name: "control plane",
        ok: true,
        detail: `reachable at ${baseUrl}${killed ? " — ⚠ kill switch is currently engaged" : " (not killed)"}`,
      },
    };
  } catch (err) {
    const timedOut = controller.signal.aborted;
    const detail = timedOut
      ? `no response from ${baseUrl} within ${timeoutMs}ms`
      : `cannot reach ${baseUrl}: ${err instanceof Error ? err.message : String(err)}`;
    return {
      reachable: false,
      check: {
        name: "control plane",
        ok: false,
        detail,
        fix:
          "start it (pnpm --filter @ownerswitchai/mcp dev:control-plane) or fix controlPlaneUrl in your config",
      },
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Proves the device credentials authenticate without registering a real veto
 * window: POST /veto with a device-valid signature but a body missing `call`
 * gets a 400 (signature accepted, request malformed on purpose) instead of a
 * 401 (signature rejected) — so this check has no side effect on the control
 * plane's state.
 */
export async function checkDeviceCredentials(
  baseUrl: string,
  device: DeviceIdentity,
  timeoutMs: number,
  fetchImpl: typeof fetch = fetch,
): Promise<DoctorCheck> {
  const body = "{}";
  const timestamp = Date.now();
  const nonce = randomBytes(12).toString("hex");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(new URL("/veto", baseUrl), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-device-id": device.id,
        "x-device-timestamp": String(timestamp),
        "x-device-nonce": nonce,
        "x-device-signature": signDeviceRequest({ deviceId: device.id, timestamp, nonce }, body, device.secret),
      },
      body,
      signal: controller.signal,
    });
    if (res.status === 401) {
      return {
        name: "device credentials",
        ok: false,
        detail: `control plane rejected device "${device.id}"'s signature (401)`,
        fix: "check device.id and device.secret match the control plane's deviceSecret (OWNERSWITCH_DEVICE_SECRET)",
      };
    }
    if (res.status === 400) {
      return { name: "device credentials", ok: true, detail: `accepted by the control plane (device "${device.id}")` };
    }
    return {
      name: "device credentials",
      ok: false,
      detail: `unexpected HTTP ${res.status} probing device credentials`,
      fix: "check the control plane's logs — this probe expects 400 (accepted) or 401 (rejected)",
    };
  } catch (err) {
    return {
      name: "device credentials",
      ok: false,
      detail: `could not reach ${baseUrl}: ${err instanceof Error ? err.message : String(err)}`,
      fix: "fix control plane reachability (see the check above) first",
    };
  } finally {
    clearTimeout(timer);
  }
}

/** Spawns the upstream command and kills it the instant the OS confirms it started — proves it's runnable without letting it do real work. */
export async function checkUpstreamSpawnable(
  upstream: UpstreamConfig,
  spawnImpl: typeof spawn = spawn,
  timeoutMs = 5000,
): Promise<DoctorCheck> {
  return new Promise((resolve) => {
    let settled = false;
    let child: ChildProcess;
    const finish = (result: DoctorCheck): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };
    const timer = setTimeout(() => {
      child?.kill("SIGKILL");
      finish({
        name: "upstream command",
        ok: false,
        detail: `"${upstream.command}" did not report starting within ${timeoutMs}ms`,
        fix: `check upstream.command/args in your config, or try running it by hand: ${upstream.command} ${(upstream.args ?? []).join(" ")}`,
      });
    }, timeoutMs);
    try {
      child = spawnImpl(upstream.command, upstream.args ?? [], {
        cwd: upstream.cwd,
        env: { ...getDefaultEnvironment(), ...(upstream.env ?? {}) },
        stdio: "ignore",
      });
    } catch (err) {
      finish({
        name: "upstream command",
        ok: false,
        detail: err instanceof Error ? err.message : String(err),
        fix: "fix upstream.command/args in your config",
      });
      return;
    }
    child.once("spawn", () => {
      child.kill("SIGTERM");
      finish({ name: "upstream command", ok: true, detail: `"${upstream.command}" is on PATH and spawnable` });
    });
    child.once("error", (err: NodeJS.ErrnoException) => {
      const detail =
        err.code === "ENOENT"
          ? `"${upstream.command}" was not found on PATH`
          : err.code === "EACCES"
            ? `"${upstream.command}" is not executable (permission denied)`
            : err.message;
      finish({
        name: "upstream command",
        ok: false,
        detail,
        fix: "fix upstream.command/args in your config, or install the missing dependency",
      });
    });
  });
}

export async function runDoctor(
  argv: string[],
  env: Record<string, string | undefined>,
  deps: DoctorDeps = {},
): Promise<DoctorCheck[]> {
  const checks: DoctorCheck[] = [checkNodeVersion(deps.nodeVersion)];

  const { check: configCheck, config } = checkConfig(argv, env, deps.readFile);
  checks.push(configCheck);
  if (config === undefined) {
    checks.push(skipped("control plane", "config did not load"));
    checks.push(skipped("device credentials", "config did not load"));
    checks.push(skipped("upstream command", "config did not load"));
    return checks;
  }

  const timeoutMs = config.timeoutMs ?? 1500;
  const { check: cpCheck, reachable } = await checkControlPlane(config.controlPlaneUrl, timeoutMs, deps.fetchImpl);
  checks.push(cpCheck);
  checks.push(
    reachable
      ? await checkDeviceCredentials(config.controlPlaneUrl, config.device, timeoutMs, deps.fetchImpl)
      : skipped("device credentials", "control plane unreachable"),
  );
  checks.push(await checkUpstreamSpawnable(config.upstream, deps.spawnImpl));
  return checks;
}

export function formatDoctorReport(checks: DoctorCheck[]): string {
  const lines = checks.map((c) => {
    const line = `${c.ok ? "✔" : "✘"} ${c.name} — ${c.detail}`;
    return c.ok || c.fix === undefined ? line : `${line}\n  → ${c.fix}`;
  });
  const allOk = checks.every((c) => c.ok);
  lines.push("");
  lines.push(allOk ? "All checks passed." : "Some checks failed — fix them before connecting an agent.");
  return lines.join("\n");
}

/** CLI entry point for `ownerswitch-mcp doctor`. Returns the process exit code. */
export async function doctorMain(argv: string[], env: Record<string, string | undefined>): Promise<number> {
  const checks = await runDoctor(argv, env);
  console.log(formatDoctorReport(checks));
  return checks.every((c) => c.ok) ? 0 : 1;
}
