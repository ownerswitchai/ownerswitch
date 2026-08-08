/**
 * `ownerswitch-mcp verify` — proves enforcement works before any agent is
 * involved, WITHOUT touching the global kill switch by default.
 *
 * Default mode exercises the exact decision path the gateway uses at runtime
 * (evaluate() + live kill state, the same functions proxy.ts calls) plus the
 * real veto lane end to end:
 *   - a call the policy allows → allowed
 *   - a call matching no rule → the fail-closed default
 *   - a veto-lane round trip: register a real window (device-signed), veto it
 *     as the owner (bearer token), confirm it reads back "vetoed" — the
 *     owner's one tap, demonstrated against the live control plane. A vetoed
 *     window is terminal and inert; nothing is left pending in front of an
 *     owner and no upstream tool ever runs.
 *
 * The global kill switch is NOT engaged unless --include-kill-test is passed.
 * That flag exists because "a killed plane denies everything" is worth
 * proving once, but a DX preflight must not casually kill a control plane
 * whose kill state persists across restarts and whose only way back is the
 * full 2GO ceremony (owner session, cooldown, TTL, single-use — see
 * control-plane/server.ts). With the flag, verify runs that real ceremony:
 * POST /restore/ceremony, wait out the cooldown, POST /restore with the
 * minted id — wrapped so that EVERY exit path (success, error, Ctrl-C)
 * checks /status and prints exact recovery commands if the plane is still
 * killed.
 *
 * The owner token comes from OWNERSWITCH_OWNER_TOKEN or an interactive
 * prompt — never a CLI flag, which would leak it into shell history and
 * process listings. It is validated up front via a harmless POST /restore
 * probe (a bogus ceremony id: 409 "restore rejected" proves the token is
 * accepted, 401 proves it is not, and neither mutates anything), so verify
 * never engages a kill it cannot undo.
 */
import { randomBytes } from "node:crypto";
import { createInterface } from "node:readline/promises";
import { signDeviceRequest } from "@ownerswitchai/control-plane";
import { evaluate } from "@ownerswitchai/gateway";
import type { Decision, Policy, ToolCall } from "@ownerswitchai/shared";
import { ConfigError, loadConfig, type OwnerSwitchMcpConfig } from "./config.js";
import type { DeviceIdentity } from "./veto-client.js";

export interface VerifyStep {
  name: string;
  ok: boolean;
  detail: string;
  skipped?: boolean;
}

export interface VerifyOptions {
  /** Engage and restore the REAL kill switch (full 2GO ceremony). Default false. */
  includeKillTest?: boolean;
}

export interface VerifyDeps {
  fetchImpl?: typeof fetch;
  now?: () => number;
  /** injectable so tests don't sit through the real ceremony cooldown */
  sleep?: (ms: number) => Promise<void>;
  /** progress lines during long waits; stderr so the report owns stdout */
  log?: (message: string) => void;
}

export interface VerifyOutcome {
  steps: VerifyStep[];
  ok: boolean;
}

const AGENT_ID = "ownerswitch-mcp-verify";
const DEFAULT_PROBE_TOOL = "__ownerswitch_verify_default_probe__";
const TOKEN_PROBE_CEREMONY_ID = "ownerswitch-verify-token-probe";

const errorMessage = (err: unknown): string => (err instanceof Error ? err.message : String(err));

/** A glob turned into one concrete tool name that matches it. */
function probeToolFor(glob: string): string {
  return glob.includes("*") ? glob.split("*").join("verify_probe") : glob;
}

async function getStatus(
  baseUrl: string,
  fetchImpl: typeof fetch,
): Promise<{ ok: true; killed: boolean } | { ok: false; error: string }> {
  try {
    const res = await fetchImpl(new URL("/status", baseUrl));
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    const body = (await res.json()) as { killed?: unknown };
    if (typeof body.killed !== "boolean") return { ok: false, error: "malformed /status response" };
    return { ok: true, killed: body.killed };
  } catch (err) {
    return { ok: false, error: errorMessage(err) };
  }
}

async function ownerPost(
  baseUrl: string,
  path: string,
  ownerToken: string,
  body: unknown,
  fetchImpl: typeof fetch,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetchImpl(new URL(path, baseUrl), {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${ownerToken}` },
    body: JSON.stringify(body),
  });
  const parsed = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  return { status: res.status, body: parsed };
}

async function ownerGet(
  baseUrl: string,
  path: string,
  ownerToken: string,
  fetchImpl: typeof fetch,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetchImpl(new URL(path, baseUrl), {
    headers: { authorization: `Bearer ${ownerToken}` },
  });
  const parsed = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  return { status: res.status, body: parsed };
}

async function deviceSignedPost(
  baseUrl: string,
  path: string,
  device: DeviceIdentity,
  body: string,
  fetchImpl: typeof fetch,
  now: () => number,
): Promise<Response> {
  const timestamp = now();
  const nonce = randomBytes(12).toString("hex");
  return fetchImpl(new URL(path, baseUrl), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-device-id": device.id,
      "x-device-timestamp": String(timestamp),
      "x-device-nonce": nonce,
      "x-device-signature": signDeviceRequest({ deviceId: device.id, timestamp, nonce }, body, device.secret),
    },
    body,
  });
}

function decisionFor(call: ToolCall, policy: Policy, killed: boolean): Decision {
  return evaluate(call, policy, { killed }).decision;
}

/** The exact commands to un-kill a plane by hand; printed whenever verify cannot guarantee it. */
function recoveryInstructions(baseUrl: string): string {
  return [
    `The kill switch may still be ENGAGED at ${baseUrl}. Every tool call is refused until it is restored.`,
    `Restarting the control plane does NOT restore it — kill state persists to disk. Run the 2GO ceremony:`,
    `  1. curl -s -X POST ${baseUrl}/restore/ceremony -H 'Authorization: Bearer <owner token>'`,
    `       → note the returned ceremony "id" (cer_...)`,
    `  2. wait out the cooldown (~30 s; GET ${baseUrl}/restore/ceremony/<id> shows cooldownRemainingMs)`,
    `  3. curl -s -X POST ${baseUrl}/restore -H 'Authorization: Bearer <owner token>' \\`,
    `       -H 'content-type: application/json' -d '{"ceremonyId":"<id>"}'`,
    `Then confirm: curl -s ${baseUrl}/status → {"killed":false}`,
  ].join("\n");
}

export async function runVerify(
  config: OwnerSwitchMcpConfig,
  ownerToken: string | undefined,
  options: VerifyOptions = {},
  deps: VerifyDeps = {},
): Promise<VerifyOutcome> {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const now = deps.now ?? Date.now;
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const log = deps.log ?? ((message: string) => console.error(message));
  const baseUrl = config.controlPlaneUrl;
  const steps: VerifyStep[] = [];
  const fail = (name: string, detail: string): VerifyOutcome => {
    steps.push({ name, ok: false, detail });
    return { steps, ok: false };
  };

  if (ownerToken === undefined || ownerToken === "") {
    return fail(
      "owner token",
      "no owner token available — set OWNERSWITCH_OWNER_TOKEN (export it for this shell, unset it when " +
        "done) or run verify in a terminal and paste the token at the prompt. The dev control plane " +
        "prints one at startup. verify uses it to play the owner's veto tap; it is never accepted as a " +
        "CLI flag, which would leak it into shell history and process listings.",
    );
  }

  const initialStatus = await getStatus(baseUrl, fetchImpl);
  if (!initialStatus.ok) {
    return fail("control plane", `cannot reach ${baseUrl}: ${initialStatus.error}`);
  }
  if (initialStatus.killed) {
    return fail(
      "control plane",
      `${baseUrl} is already in lockdown — every call is refused until an owner restores it. ` +
        `verify needs a normal starting state.\n${recoveryInstructions(baseUrl)}`,
    );
  }

  // Harmless owner-token probe: POST /restore with a ceremony id the server
  // can never have minted. A valid token gets the uniform 409 "restore
  // rejected" (nothing consumed, nothing restored — there is no such
  // ceremony); an invalid one gets 401. Neither mutates any state.
  const probe = await ownerPost(
    baseUrl,
    "/restore",
    ownerToken,
    { ceremonyId: TOKEN_PROBE_CEREMONY_ID },
    fetchImpl,
  );
  if (probe.status === 401) {
    return fail(
      "owner token",
      "control plane rejected the owner token (401) — it expires 15 minutes after the control plane " +
        "prints it; grab the current one and re-run",
    );
  }
  if (probe.status !== 409) {
    return fail(
      "owner token",
      `unexpected HTTP ${probe.status} from the token probe (expected the uniform 409 rejection)`,
    );
  }
  steps.push({ name: "owner token", ok: true, detail: "accepted by the control plane" });

  const policy = config.policy;
  const allowRule = policy.rules.find((r) => r.decision === "allow");
  const allowCall: ToolCall | undefined = allowRule
    ? { agentId: AGENT_ID, tool: probeToolFor(allowRule.tool) }
    : undefined;

  if (allowCall === undefined) {
    steps.push({
      name: "allow call",
      ok: true,
      skipped: true,
      detail: `skipped — policy has no "allow" rule to build a demonstration call from`,
    });
  } else {
    const decision = decisionFor(allowCall, policy, false);
    steps.push({
      name: "allow call",
      ok: decision === "allow",
      detail:
        decision === "allow"
          ? `"${allowCall.tool}" (rule "${allowRule!.id}") → allowed, as configured`
          : `"${allowCall.tool}" (rule "${allowRule!.id}") → expected "allow", got "${decision}"`,
    });
  }

  const defaultCall: ToolCall = { agentId: AGENT_ID, tool: DEFAULT_PROBE_TOOL };
  const defaultVerdict = evaluate(defaultCall, policy, { killed: false });
  if (defaultVerdict.ruleId !== null) {
    steps.push({
      name: "default decision",
      ok: true,
      skipped: true,
      detail: `skipped — every tool name matches an explicit rule in this policy (e.g. a catch-all), so the fail-closed default can't be exercised`,
    });
  } else {
    steps.push({
      name: "default decision",
      ok: defaultVerdict.decision !== "allow",
      detail:
        defaultVerdict.decision !== "allow"
          ? `unmatched tool → "${defaultVerdict.decision}", as configured (defaultDecision)`
          : `unmatched tool → "allow" — defaultDecision is "allow", so unknown tools are NOT fail-closed`,
    });
  }

  // The veto lane, end to end and kill-free: register a real window as the
  // gateway would (device-signed), stop it with the owner's one tap, and
  // read the terminal state back. Proves device credentials, the owner
  // token's authority, and that a vetoed call STAYS vetoed — the whole
  // owner-in-the-loop story without touching the kill switch. The residue is
  // one terminally-vetoed demo window in the control plane's in-memory map.
  const vetoRule = policy.rules.find((r) => r.decision === "veto");
  const vetoTool = vetoRule ? probeToolFor(vetoRule.tool) : "__ownerswitch_verify_veto_probe__";
  const vetoPolicyNote = vetoRule
    ? `rule "${vetoRule.id}" holds "${vetoTool}" for the owner`
    : `policy has no "veto" rule, so this exercises the lane mechanics only`;
  if (vetoRule !== undefined) {
    const decision = decisionFor({ agentId: AGENT_ID, tool: vetoTool }, policy, false);
    if (decision !== "veto") {
      steps.push({
        name: "veto lane",
        ok: false,
        detail: `"${vetoTool}" (rule "${vetoRule.id}") → expected "veto", got "${decision}"`,
      });
      return { steps, ok: false };
    }
  }
  try {
    const registerBody = JSON.stringify({
      call: { agentId: AGENT_ID, tool: vetoTool, args: { note: "ownerswitch-mcp verify demo window" } },
    });
    const registerRes = await deviceSignedPost(baseUrl, "/veto", config.device, registerBody, fetchImpl, now);
    if (registerRes.status === 401) {
      steps.push({
        name: "veto lane",
        ok: false,
        detail:
          "control plane rejected this gateway's device credentials registering the demo window (401) — " +
          "check device.id and device.secret against the control plane's device secret",
      });
      return { steps, ok: false };
    }
    if (registerRes.status !== 201) {
      steps.push({
        name: "veto lane",
        ok: false,
        detail: `window registration failed (HTTP ${registerRes.status})`,
      });
      return { steps, ok: false };
    }
    const windowId = ((await registerRes.json()) as { id?: unknown }).id;
    if (typeof windowId !== "string" || windowId === "") {
      steps.push({ name: "veto lane", ok: false, detail: "window registration returned no id" });
      return { steps, ok: false };
    }
    const tap = await ownerPost(baseUrl, `/veto/${encodeURIComponent(windowId)}`, ownerToken, {}, fetchImpl);
    if (tap.status !== 200 || tap.body.status !== "vetoed") {
      steps.push({
        name: "veto lane",
        ok: false,
        detail: `owner veto tap on window "${windowId}" failed (HTTP ${tap.status}, status "${String(tap.body.status ?? tap.body.error)}")`,
      });
      return { steps, ok: false };
    }
    const readBack = await fetchImpl(new URL(`/veto/${encodeURIComponent(windowId)}`, baseUrl));
    const readStatus = ((await readBack.json().catch(() => ({}))) as { status?: unknown }).status;
    steps.push({
      name: "veto lane",
      ok: readStatus === "vetoed",
      detail:
        readStatus === "vetoed"
          ? `window "${windowId}" registered (device-signed), vetoed by the owner's tap, reads back "vetoed" — ${vetoPolicyNote}`
          : `window "${windowId}" was vetoed but reads back "${String(readStatus)}"`,
    });
  } catch (err) {
    steps.push({ name: "veto lane", ok: false, detail: `control plane call failed: ${errorMessage(err)}` });
    return { steps, ok: false };
  }

  if (options.includeKillTest === true) {
    await runKillTest(config, ownerToken, steps, { fetchImpl, now, sleep, log });
  }

  return { steps, ok: steps.every((s) => s.ok) };
}

/**
 * The opt-in kill-switch exercise. Engages the REAL kill switch, proves a
 * previously-allowed call is refused, then restores through the REAL 2GO
 * ceremony. The finally block plus a temporary SIGINT handler guarantee that
 * every exit path ends with a /status check — and loud, exact recovery
 * instructions if the plane is still killed.
 */
async function runKillTest(
  config: OwnerSwitchMcpConfig,
  ownerToken: string,
  steps: VerifyStep[],
  deps: Required<Pick<VerifyDeps, "fetchImpl" | "now" | "sleep" | "log">>,
): Promise<void> {
  const { fetchImpl, now, sleep, log } = deps;
  const baseUrl = config.controlPlaneUrl;

  const killBody = JSON.stringify({ reason: "ownerswitch-mcp verify --include-kill-test", source: "api" });
  try {
    const res = await deviceSignedPost(baseUrl, "/kill", config.device, killBody, fetchImpl, now);
    if (!res.ok) throw new Error(`control plane refused kill (HTTP ${res.status})`);
  } catch (err) {
    steps.push({
      name: "kill switch",
      ok: false,
      detail: `could not engage the kill switch to test it: ${errorMessage(err)} (system state unchanged)`,
    });
    return;
  }

  // From here the plane is really killed; nothing below may return without
  // the finally confirming the restore or printing how to do it by hand.
  const onSigint = (): void => {
    void (async () => {
      const status = await getStatus(baseUrl, fetchImpl).catch(() => null);
      if (status === null || !status.ok || status.killed) log(`\n${recoveryInstructions(baseUrl)}`);
      process.exit(130);
    })();
  };
  process.once("SIGINT", onSigint);

  try {
    const afterKill = await getStatus(baseUrl, fetchImpl);
    const killConfirmed = afterKill.ok && afterKill.killed;
    const allowRule = config.policy.rules.find((r) => r.decision === "allow");
    const probeTool = allowRule ? probeToolFor(allowRule.tool) : DEFAULT_PROBE_TOOL;
    const refused =
      decisionFor({ agentId: AGENT_ID, tool: probeTool }, config.policy, killConfirmed) === "deny";
    steps.push({
      name: "kill switch",
      ok: killConfirmed && refused,
      detail: !killConfirmed
        ? "engaged, but /status does not report killed:true"
        : refused
          ? `engaged — "${probeTool}" (previously allowed) is now refused; restoring via the 2GO ceremony…`
          : `engaged, but "${probeTool}" still evaluated as allowed — enforcement is NOT fail-closed`,
    });

    // The real ceremony: GO 1/2, wait out the server's cooldown, GO 2/2.
    const started = await ownerPost(baseUrl, "/restore/ceremony", ownerToken, {}, fetchImpl);
    if ((started.status !== 201 && started.status !== 200) || typeof started.body.id !== "string") {
      steps.push({
        name: "restore ceremony",
        ok: false,
        detail: `POST /restore/ceremony failed (HTTP ${started.status}: ${String(started.body.error ?? "no detail")})`,
      });
      return;
    }
    const ceremonyId = started.body.id;
    const expiresAt = typeof started.body.expiresAt === "number" ? started.body.expiresAt : now() + 5 * 60_000;
    let cooldown =
      typeof started.body.cooldownRemainingMs === "number" ? started.body.cooldownRemainingMs : 30_000;
    while (cooldown > 0) {
      log(`[verify] ceremony ${ceremonyId} minted — waiting out the ${Math.ceil(cooldown / 1000)}s cooldown…`);
      await sleep(cooldown + 250);
      const state = await ownerGet(baseUrl, `/restore/ceremony/${encodeURIComponent(ceremonyId)}`, ownerToken, fetchImpl);
      if (state.status !== 200) {
        steps.push({
          name: "restore ceremony",
          ok: false,
          detail: `ceremony status read failed (HTTP ${state.status})`,
        });
        return;
      }
      if (state.body.state === "ready") break;
      if (state.body.state !== "go1" || now() > expiresAt) {
        steps.push({
          name: "restore ceremony",
          ok: false,
          detail: `ceremony ended in state "${String(state.body.state)}" before GO 2/2`,
        });
        return;
      }
      cooldown = typeof state.body.cooldownRemainingMs === "number" ? state.body.cooldownRemainingMs : 500;
    }
    const restored = await ownerPost(baseUrl, "/restore", ownerToken, { ceremonyId }, fetchImpl);
    steps.push({
      name: "restore ceremony",
      ok: restored.status === 200,
      detail:
        restored.status === 200
          ? `ceremony ${ceremonyId} completed GO 2/2 — control plane restored`
          : `POST /restore rejected (HTTP ${restored.status}: ${String(restored.body.error ?? "no detail")})`,
    });
  } finally {
    process.removeListener("SIGINT", onSigint);
    // The one check that must ALWAYS run: is the plane back to killed:false?
    const finalStatus = await getStatus(baseUrl, fetchImpl).catch(() => null);
    const restored = finalStatus !== null && finalStatus.ok && !finalStatus.killed;
    steps.push({
      name: "final state",
      ok: restored,
      detail: restored
        ? "control plane is back to killed:false — the system ends in the state it started in"
        : `control plane is STILL KILLED.\n${recoveryInstructions(baseUrl)}`,
    });
  }
}

export function formatVerifyReport(outcome: VerifyOutcome): string {
  const lines = outcome.steps.map((s) => {
    const icon = s.skipped ? "…" : s.ok ? "✔" : "✘";
    return `${icon} ${s.name} — ${s.detail}`;
  });
  lines.push("");
  lines.push(
    outcome.ok
      ? "PASS — enforcement is working. Safe to point an agent at this gateway."
      : "FAIL — do not connect an agent yet.",
  );
  return lines.join("\n");
}

/**
 * The owner token, from the environment or an interactive prompt — never
 * argv, which `ps` and shell history record.
 */
export async function resolveOwnerToken(
  env: Record<string, string | undefined>,
  promptImpl?: () => Promise<string | undefined>,
): Promise<string | undefined> {
  const fromEnv = env.OWNERSWITCH_OWNER_TOKEN?.trim();
  if (fromEnv !== undefined && fromEnv !== "") return fromEnv;
  const prompt = promptImpl ?? promptOwnerTokenFromTty;
  return prompt();
}

async function promptOwnerTokenFromTty(): Promise<string | undefined> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) return undefined;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await rl.question("Owner token (printed by the control plane at startup): ");
    const trimmed = answer.trim();
    return trimmed === "" ? undefined : trimmed;
  } finally {
    rl.close();
  }
}

/** CLI entry point for `ownerswitch-mcp verify`. Returns the process exit code. */
export async function verifyMain(argv: string[], env: Record<string, string | undefined>): Promise<number> {
  let includeKillTest = false;
  const rest: string[] = [];
  for (const arg of argv) {
    if (arg === "--include-kill-test") {
      includeKillTest = true;
    } else if (arg === "--owner-token" || arg.startsWith("--owner-token=")) {
      console.error(
        "[ownerswitch-mcp verify] --owner-token was removed: a token on the command line leaks into " +
          "shell history and process listings. Set OWNERSWITCH_OWNER_TOKEN, or run verify in a " +
          "terminal and paste the token at the prompt.",
      );
      return 1;
    } else {
      rest.push(arg);
    }
  }
  let config: OwnerSwitchMcpConfig;
  try {
    config = loadConfig(rest, env);
  } catch (err) {
    console.error(`[ownerswitch-mcp verify] config error: ${err instanceof ConfigError ? err.message : errorMessage(err)}`);
    return 1;
  }
  const ownerToken = await resolveOwnerToken(env);
  const outcome = await runVerify(config, ownerToken, { includeKillTest });
  console.log(formatVerifyReport(outcome));
  return outcome.ok ? 0 : 1;
}
