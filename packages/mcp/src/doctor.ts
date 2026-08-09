/**
 * `ownerswitch-mcp doctor` — a preflight check, run by hand before you ever
 * point an MCP client at the gateway. Every non-passing line says what to do
 * about it: the goal is that nobody has to ask an agent to debug their own
 * connection (which burns the agent's quota diagnosing infrastructure, not
 * doing the task).
 */
import { randomBytes } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { signDeviceRequest } from "@ownerswitchai/control-plane";
import { ConfigError, loadConfig, type OwnerSwitchMcpConfig, type UpstreamConfig } from "./config.js";
import type { DeviceIdentity } from "./veto-client.js";

/**
 * "pass" renders ✔. "fail" renders ✘. "action" renders ⚠ — the check's
 * subject responded, but in a state you must act on before connecting an
 * agent (e.g. a reachable control plane whose kill switch is engaged). A
 * bare ✔ there would send the reader straight into verify refusing to run.
 * Anything other than "pass" fails the doctor run as a whole.
 */
export interface DoctorCheck {
  name: string;
  status: "pass" | "action" | "fail";
  detail: string;
  /** what to do about it — required whenever status is not "pass" */
  fix?: string;
}

export interface UpstreamProbeOptions {
  /** give up on the MCP initialize handshake after this long; default 15s */
  timeoutMs?: number;
  /** injectable for tests — defaults to a real stdio transport for the upstream command */
  transportFactory?: (upstream: UpstreamConfig) => Transport;
}

export interface DoctorDeps {
  fetchImpl?: typeof fetch;
  readFile?: (path: string) => string;
  nodeVersion?: string;
  upstreamProbe?: UpstreamProbeOptions;
}

const MIN_NODE_MAJOR = 22;

const skipped = (name: string, why: string): DoctorCheck => ({
  name,
  status: "fail",
  detail: `skipped — ${why}`,
  fix: "fix the failing check above first, then re-run doctor",
});

export function checkNodeVersion(nodeVersion = process.versions.node): DoctorCheck {
  const major = Number(nodeVersion.split(".")[0]);
  if (major >= MIN_NODE_MAJOR) {
    return { name: "node version", status: "pass", detail: `v${nodeVersion} (>= ${MIN_NODE_MAJOR} required)` };
  }
  return {
    name: "node version",
    status: "fail",
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
        status: "pass",
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
        status: "fail",
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
    // /status is live security state — never accept a cached answer
    const res = await fetchImpl(new URL("/status", baseUrl), {
      signal: controller.signal,
      cache: "no-store",
    });
    if (!res.ok) {
      return {
        reachable: false,
        check: {
          name: "control plane",
          status: "fail",
          detail: `${baseUrl} responded HTTP ${res.status}`,
          fix: "check controlPlaneUrl in your config and that the control plane process is healthy",
        },
      };
    }
    const body = (await res.json().catch(() => null)) as { killed?: unknown; reason?: unknown } | null;
    if (body?.killed === true) {
      // Reachable, but everything is refused: NOT a pass. The quickstart
      // gates on "every line ✔", and verify refuses to start from a killed
      // plane — so this state must be called out here, with the way back.
      const reason = typeof body.reason === "string" ? ` (reason: ${body.reason})` : "";
      return {
        reachable: true,
        check: {
          name: "control plane",
          status: "action",
          detail: `reachable at ${baseUrl} — but the kill switch is ENGAGED${reason}; every tool call is refused (-32054)`,
          fix:
            "restore it with the 2GO ceremony before connecting an agent: POST /restore/ceremony " +
            "(owner token), wait out the ~30s cooldown, then POST /restore with the minted ceremony id — " +
            "see the README's verify section for the exact curl commands. Restarting the control plane " +
            "does NOT restore it; kill state persists to disk.",
        },
      };
    }
    return {
      reachable: true,
      check: {
        name: "control plane",
        status: "pass",
        detail: `reachable at ${baseUrl} (not killed)`,
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
        status: "fail",
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
        status: "fail",
        detail: `control plane rejected device "${device.id}"'s signature (401)`,
        fix: "check device.id and device.secret match the control plane's deviceSecret (OWNERSWITCH_DEVICE_SECRET)",
      };
    }
    if (res.status === 400) {
      return {
        name: "device credentials",
        status: "pass",
        detail: `accepted by the control plane (device "${device.id}")`,
      };
    }
    return {
      name: "device credentials",
      status: "fail",
      detail: `unexpected HTTP ${res.status} probing device credentials`,
      fix: "check the control plane's logs — this probe expects 400 (accepted) or 401 (rejected)",
    };
  } catch (err) {
    return {
      name: "device credentials",
      status: "fail",
      detail: `could not reach ${baseUrl}: ${err instanceof Error ? err.message : String(err)}`,
      fix: "fix control plane reachability (see the check above) first",
    };
  } finally {
    clearTimeout(timer);
  }
}

class HandshakeTimeout extends Error {}

/**
 * Proves the upstream is a working MCP server, not merely a spawnable
 * binary: launches it exactly as the gateway will and completes a real MCP
 * initialize handshake, then shuts it down through the SDK's close path
 * (stdin end → wait for exit → escalate only if it lingers). A spawn-event
 * check would pass for any executable that starts — including one that
 * crashes on boot or never speaks MCP, which the MCP client would then
 * report as an opaque connection timeout.
 */
export async function checkUpstreamHandshake(
  upstream: UpstreamConfig,
  options: UpstreamProbeOptions = {},
): Promise<DoctorCheck> {
  const timeoutMs = options.timeoutMs ?? 15_000;
  const stderrChunks: string[] = [];
  const transportFactory =
    options.transportFactory ??
    ((u: UpstreamConfig): Transport => {
      const transport = new StdioClientTransport({
        command: u.command,
        args: u.args ?? [],
        env: { ...getDefaultEnvironment(), ...(u.env ?? {}) },
        cwd: u.cwd,
        stderr: "pipe",
      });
      transport.stderr?.on("data", (chunk: Buffer) => {
        stderrChunks.push(chunk.toString("utf8"));
        while (stderrChunks.length > 8) stderrChunks.shift();
      });
      return transport;
    });

  const stderrTail = (): string => {
    const tail = stderrChunks.join("").trim().split("\n").slice(-3).join("\n  ");
    return tail === "" ? "" : `\n  upstream stderr: ${tail}`;
  };

  let transport: Transport;
  try {
    transport = transportFactory(upstream);
  } catch (err) {
    return {
      name: "upstream command",
      status: "fail",
      detail: err instanceof Error ? err.message : String(err),
      fix: "fix upstream.command/args in your config",
    };
  }

  const client = new Client({ name: "ownerswitch-mcp doctor", version: "0.0.1" });
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new HandshakeTimeout()), timeoutMs);
  });
  try {
    await Promise.race([client.connect(transport), timeout]);
    // Clean shutdown: the SDK ends the child's stdin and WAITS for it to
    // exit, escalating to signals only if it does not go on its own.
    await client.close();
    return {
      name: "upstream command",
      status: "pass",
      detail: `"${upstream.command}" answered the MCP initialize handshake and shut down cleanly`,
    };
  } catch (err) {
    await client.close().catch(() => {});
    if (err instanceof HandshakeTimeout) {
      return {
        name: "upstream command",
        status: "fail",
        detail: `"${upstream.command}" did not answer the MCP initialize handshake within ${timeoutMs}ms${stderrTail()}`,
        fix: `check that upstream.command/args launch a stdio MCP server; try it by hand: ${upstream.command} ${(upstream.args ?? []).join(" ")}`,
      };
    }
    const code = (err as NodeJS.ErrnoException).code;
    const detail =
      code === "ENOENT"
        ? `"${upstream.command}" was not found on PATH`
        : code === "EACCES"
          ? `"${upstream.command}" is not executable (permission denied)`
          : `${err instanceof Error ? err.message : String(err)}${stderrTail()}`;
    return {
      name: "upstream command",
      status: "fail",
      detail,
      fix: "fix upstream.command/args in your config, or install the missing dependency",
    };
  } finally {
    clearTimeout(timer);
  }
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
  checks.push(await checkUpstreamHandshake(config.upstream, deps.upstreamProbe));
  return checks;
}

export function formatDoctorReport(checks: DoctorCheck[]): string {
  const icons = { pass: "✔", action: "⚠", fail: "✘" } as const;
  const lines = checks.map((c) => {
    const line = `${icons[c.status]} ${c.name} — ${c.detail}`;
    return c.status === "pass" || c.fix === undefined ? line : `${line}\n  → ${c.fix}`;
  });
  const allPass = checks.every((c) => c.status === "pass");
  const anyAction = checks.some((c) => c.status === "action");
  lines.push("");
  lines.push(
    allPass
      ? "All checks passed."
      : anyAction && checks.every((c) => c.status !== "fail")
        ? "Action required — resolve the ⚠ line(s) before connecting an agent."
        : "Some checks failed — fix them before connecting an agent.",
  );
  return lines.join("\n");
}

/** CLI entry point for `ownerswitch-mcp doctor`. Returns the process exit code. */
export async function doctorMain(argv: string[], env: Record<string, string | undefined>): Promise<number> {
  const checks = await runDoctor(argv, env);
  console.log(formatDoctorReport(checks));
  return checks.every((c) => c.status === "pass") ? 0 : 1;
}
