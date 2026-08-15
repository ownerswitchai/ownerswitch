/**
 * `ownerswitch-mcp doctor` — a preflight check, run by hand before you ever
 * point an MCP client at the gateway. Every non-passing line says what to do
 * about it: the goal is that nobody has to ask an agent to debug their own
 * connection (which burns the agent's quota diagnosing infrastructure, not
 * doing the task).
 */
import { randomBytes } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { signDeviceRequest } from "@ownerswitchai/control-plane";
import { ConfigError, loadConfig, type OwnerSwitchMcpConfig } from "./config.js";
import {
  runStartupGates,
  type StartupGateDeps,
  type StartupGateResult,
} from "./startup-gates.js";
import { upstreamLaunchSpec, type UpstreamLaunchSpec } from "./upstream-env.js";
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
  /** injectable for tests — defaults to a real stdio transport for the spec */
  transportFactory?: (spec: UpstreamLaunchSpec) => Transport;
  /** the ambient environment to diagnose a stripped-env failure against */
  env?: Record<string, string | undefined>;
}

/**
 * Environment variables that commonly decide whether a command can reach
 * the network or a registry AT ALL, and that the upstream child does NOT
 * inherit: the MCP SDK spawns it with `getDefaultEnvironment()`, an
 * allowlist of roughly HOME/LOGNAME/PATH/SHELL/TERM/USER. Everything else
 * must be declared in `upstream.env`.
 *
 * This is the single most confusing failure in the whole setup, because the
 * evidence points the wrong way: the identical command run by hand works,
 * so the config "must" be right — and the only symptom is a handshake that
 * never answers. Naming the variables that ARE set here but not passed
 * through turns a 15-second silence into one line to copy.
 */
const ENV_THE_CHILD_DOES_NOT_INHERIT = [
  "HTTPS_PROXY",
  "https_proxy",
  "HTTP_PROXY",
  "http_proxy",
  "NO_PROXY",
  "no_proxy",
  "NODE_EXTRA_CA_CERTS",
  "SSL_CERT_FILE",
  "NPM_CONFIG_REGISTRY",
  "npm_config_registry",
  "NODE_OPTIONS",
  "NVM_BIN",
] as const;

/**
 * Ambient vars the child will NOT have — computed against the environment
 * the child ACTUALLY gets, not against what the config declares. Those
 * differ in the case that matters most: a variable declared in
 * `upstream.env` but stripped as a credential is missing from the child,
 * and saying "you declared it" would send the reader looking in the wrong
 * place.
 */
export function undeclaredUpstreamEnv(
  childEnv: Record<string, string>,
  env: Record<string, string | undefined> = process.env,
): string[] {
  return ENV_THE_CHILD_DOES_NOT_INHERIT.filter(
    (name) => env[name] !== undefined && env[name] !== "" && childEnv[name] === undefined,
  );
}

export interface DoctorDeps {
  fetchImpl?: typeof fetch;
  readFile?: (path: string) => string;
  nodeVersion?: string;
  upstreamProbe?: UpstreamProbeOptions;
  startupGates?: StartupGateDeps;
}

const MIN_NODE_MAJOR = 22;

/** commands whose FIRST run may download the server before it speaks MCP */
const PACKAGE_RUNNERS = new Set(["npx", "pnpx", "bunx", "pnpm", "yarn"]);

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

/**
 * The gateway's SHARED, PURE configuration gates — everything it validates
 * before serving that is a function of config and environment alone — run
 * here instead of at launch. (Runtime construction and connection failures
 * are not gates and cannot be checked this way; the control-plane, device
 * and upstream checks below cover what can.) Without this, a config that
 * parses but trips a startup gate
 * produced the worst outcome doctor can produce: "All checks passed",
 * followed by an MCP client reporting nothing but a closed connection —
 * because the gateway's refusal went to a stderr the client swallows.
 *
 * Pure validation only (startup-gates.ts): no sockets, no spawns, no writes.
 */
export function checkStartupGates(
  config: OwnerSwitchMcpConfig,
  env: Record<string, string | undefined>,
  deps: StartupGateDeps = {},
): { check: DoctorCheck; gates?: StartupGateResult } {
  let gates: StartupGateResult;
  try {
    gates = runStartupGates(config, env, deps);
  } catch (err) {
    return {
      check: {
        name: "startup gates",
        status: "fail",
        detail: err instanceof ConfigError || err instanceof Error ? err.message : String(err),
        // The detail IS the instruction — these messages name the flag, file
        // or variable to fix. What people need told is that this is not a
        // doctor-only complaint: the gateway refuses to start on it, and an
        // MCP client will show that only as a dead connection.
        fix: "the gateway REFUSES TO START until this is resolved — an MCP client would show it only as a closed connection or a timeout",
      },
    };
  }
  {
    const { connector, honeytokenRegistry } = gates;
    const armed = [
      config.limits !== undefined && config.limits.length > 0
        ? `${config.limits.length} limit rule(s)`
        : undefined,
      honeytokenRegistry !== undefined ? "honeytoken registry" : undefined,
      connector !== undefined ? `github connector (${connector.mode})` : undefined,
      config.executorRoutes !== undefined && Object.keys(config.executorRoutes).length > 0
        ? `${Object.keys(config.executorRoutes).length} executor route(s)`
        : undefined,
    ].filter((s): s is string => s !== undefined);
    return {
      gates,
      check: {
        name: "startup gates",
        status: "pass",
        detail:
          armed.length === 0
            ? "nothing beyond policy is armed — the gateway will start"
            : `the gateway will start with ${armed.join(", ")}`,
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
          // The commands, not a pointer to them: a restore rejection answers
          // a deliberately uniform 409 ("restore rejected") that never says
          // WHICH check failed, so someone guessing at the ceremony gets no
          // feedback to guess with. The one honest way through is to run it
          // in the right order and read the ceremony's own state.
          fix:
            "restore it with the 2GO ceremony before connecting an agent (OWNER=your owner token):\n" +
            `      CER=$(curl -fsS -X POST ${baseUrl}/restore/ceremony -H "Authorization: Bearer $OWNER" | jq -r .id)\n` +
            `      curl -fsS ${baseUrl}/restore/ceremony/$CER -H "Authorization: Bearer $OWNER"   # cooldownRemainingMs\n` +
            "      # wait out the ~30s cooldown, then:\n" +
            `      curl -fsS -X POST ${baseUrl}/restore -H "Authorization: Bearer $OWNER" ` +
            '-H "content-type: application/json" -d "{\\"ceremonyId\\":\\"$CER\\"}"\n' +
            "    A restore attempted early answers 409 {\"error\":\"restore rejected\"} — the body never says " +
            "which check failed, by design; the ceremony's own cooldownRemainingMs above is the thing to read. " +
            "Restarting the control plane does NOT restore it; kill state persists to disk.",
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
        "x-device-signature": signDeviceRequest({ deviceId: device.id, timestamp, nonce }, body, device.secret, {
          method: "POST",
          pathAndQuery: "/veto",
        }),
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
  spec: UpstreamLaunchSpec,
  options: UpstreamProbeOptions = {},
): Promise<DoctorCheck> {
  const timeoutMs = options.timeoutMs ?? 15_000;
  const stderrChunks: string[] = [];
  // The child's environment is an ALLOWLIST, not an inheritance — and it is
  // the SAME environment the gateway builds, credential strip included,
  // because both come from upstreamLaunchSpec. Anything ambient and
  // load-bearing that the child will not get is the first thing to suspect
  // when a command that works by hand goes silent here.
  const missingEnv = undeclaredUpstreamEnv(spec.env, options.env ?? process.env);
  const envHint =
    missingEnv.length === 0
      ? "the upstream child runs with a STRIPPED environment (roughly HOME/PATH/SHELL/TERM/USER — " +
        "not your shell's); anything else it needs must be declared in upstream.env"
      : `the upstream child runs with a STRIPPED environment, so these are set in YOUR shell but NOT ` +
        `passed to it: ${missingEnv.join(", ")}. If the same command works by hand, that difference is ` +
        `the likely cause — declare what it needs in upstream.env`;
  const transportFactory =
    options.transportFactory ??
    ((s: UpstreamLaunchSpec): Transport => {
      // EXACTLY what the gateway spawns (upstreamLaunchSpec), differing only
      // in stderr handling: the probe captures the tail to quote it back.
      const transport = new StdioClientTransport({ ...s, stderr: "pipe" });
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
    transport = transportFactory(spec);
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
      detail: `"${spec.command}" answered the MCP initialize handshake and shut down cleanly`,
    };
  } catch (err) {
    await client.close().catch(() => {});
    if (err instanceof HandshakeTimeout) {
      return {
        name: "upstream command",
        status: "fail",
        detail: `"${spec.command}" did not answer the MCP initialize handshake within ${timeoutMs}ms${stderrTail()}`,
        fix:
          `${envHint}.\n` +
          `    Then check the command itself launches a stdio MCP server — try it by hand: ` +
          `${spec.command} ${spec.args.join(" ")}` +
          // the download note only where it can apply: a package runner's
          // first run fetches before it speaks; for any other command the
          // sentence would just send the reader chasing the wrong cause
          (PACKAGE_RUNNERS.has(spec.command)
            ? `\n    A first "${spec.command} -y <package>" run also downloads before it speaks; ` +
              `--upstream-timeout <ms> raises the ${timeoutMs}ms budget if that is all it is (or ` +
              `use the in-repo demo upstream, examples/demo-tools-server.ts, which downloads nothing)`
            : ""),
      };
    }
    const code = (err as NodeJS.ErrnoException).code;
    const detail =
      code === "ENOENT"
        ? `"${spec.command}" was not found on PATH`
        : code === "EACCES"
          ? `"${spec.command}" is not executable (permission denied)`
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
    checks.push(skipped("startup gates", "config did not load"));
    checks.push(skipped("control plane", "config did not load"));
    checks.push(skipped("device credentials", "config did not load"));
    checks.push(skipped("upstream command", "config did not load"));
    return checks;
  }

  // Second, before anything touches the network OR SPAWNS ANYTHING: would
  // the gateway even start with this config and environment? A green run
  // that ends in a refusing gateway is the failure mode doctor exists to
  // remove — and a gate failure must stop the run, not annotate it. One of
  // these gates refuses BECAUSE upstream.args carries a credential; probing
  // the upstream anyway would perform the very /proc-and-ps leak the gate
  // just diagnosed. Nothing downstream runs.
  const { check: gatesCheck, gates } = checkStartupGates(config, env, deps.startupGates);
  checks.push(gatesCheck);
  if (gates === undefined) {
    const why = "the gateway would refuse to start — resolve the startup gate above";
    checks.push(skipped("control plane", why));
    checks.push(skipped("device credentials", why));
    checks.push(skipped("upstream command", why));
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
  checks.push(
    // the gateway's own launch spec, credential strip included — a preflight
    // must never hand the child more than the gateway would
    await checkUpstreamHandshake(upstreamLaunchSpec(config.upstream, gates.secretValues), {
      env,
      ...upstreamTimeoutFrom(argv, env),
      ...deps.upstreamProbe,
    }),
  );
  return checks;
}

/**
 * `--upstream-timeout <ms>` (or OWNERSWITCH_UPSTREAM_TIMEOUT_MS) — raises
 * the handshake budget for an upstream whose FIRST run is slow: `npx -y
 * <package>` downloads before it speaks, and on a cold cache or a slow link
 * that can outlast the default. A garbage value is ignored rather than
 * fatal: this is a preflight tool, and refusing to run over a malformed
 * flag would be the least helpful thing it could do.
 */
export function upstreamTimeoutFrom(
  argv: string[],
  env: Record<string, string | undefined>,
): { timeoutMs?: number } {
  const flagAt = argv.indexOf("--upstream-timeout");
  const raw = flagAt >= 0 ? argv[flagAt + 1] : env.OWNERSWITCH_UPSTREAM_TIMEOUT_MS;
  const ms = Number(raw);
  return raw !== undefined && Number.isSafeInteger(ms) && ms > 0 ? { timeoutMs: ms } : {};
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
