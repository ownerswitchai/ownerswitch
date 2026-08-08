/**
 * `ownerswitch-mcp verify` — proves enforcement works before any agent is
 * involved. It exercises the exact decision path the gateway uses at
 * runtime (evaluate() + live kill-state lookup, the same functions proxy.ts
 * calls) against three cases: a call the policy allows, a call that falls
 * through to the fail-closed default, and an allowed call after the kill
 * switch engages. It never forwards a call to a real upstream tool — only
 * the OwnerSwitch decision layer is under test here.
 *
 * Engaging the kill switch needs restoring afterward, and restore is
 * deliberately expensive (owner-session only, see control-plane/server.ts) —
 * so verify requires an owner token up front and validates it *before*
 * touching the kill switch, so it never engages a kill it can't undo.
 */
import { randomBytes } from "node:crypto";
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

export interface VerifyDeps {
  fetchImpl?: typeof fetch;
  now?: () => number;
}

export interface VerifyOutcome {
  steps: VerifyStep[];
  ok: boolean;
}

const AGENT_ID = "ownerswitch-mcp-verify";
const DEFAULT_PROBE_TOOL = "__ownerswitch_verify_default_probe__";

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

async function restoreProbe(
  baseUrl: string,
  ownerToken: string,
  auth: { ceremonyId: string; ownerId: string; completedAt: number },
  fetchImpl: typeof fetch,
): Promise<{ status: number; error?: string }> {
  const res = await fetchImpl(new URL("/restore", baseUrl), {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${ownerToken}` },
    body: JSON.stringify(auth),
  });
  if (res.ok) return { status: res.status };
  const parsed = (await res.json().catch(() => ({}))) as { error?: string };
  return { status: res.status, error: parsed.error };
}

function decisionFor(call: ToolCall, policy: Policy, killed: boolean): Decision {
  return evaluate(call, policy, { killed }).decision;
}

export async function runVerify(
  config: OwnerSwitchMcpConfig,
  ownerToken: string | undefined,
  deps: VerifyDeps = {},
): Promise<VerifyOutcome> {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const now = deps.now ?? Date.now;
  const baseUrl = config.controlPlaneUrl;
  const steps: VerifyStep[] = [];
  const fail = (name: string, detail: string): VerifyOutcome => {
    steps.push({ name, ok: false, detail });
    return { steps, ok: false };
  };

  if (ownerToken === undefined || ownerToken === "") {
    return fail(
      "owner token",
      "no owner token given — pass --owner-token <token> or set OWNERSWITCH_OWNER_TOKEN. " +
        "The dev control plane prints one at startup (pnpm --filter @ownerswitchai/mcp dev:control-plane). " +
        "verify needs it to restore the kill switch after testing it — it will not engage a kill it can't undo.",
    );
  }

  const initialStatus = await getStatus(baseUrl, fetchImpl);
  if (!initialStatus.ok) {
    return fail("control plane", `cannot reach ${baseUrl}: ${initialStatus.error}`);
  }
  if (initialStatus.killed) {
    return fail(
      "control plane",
      `${baseUrl} is already in lockdown — restore it first (verify needs to start from a normal state to test the kill-switch transition)`,
    );
  }

  // Harmless probe: /restore while NOT killed rejects with 409 "not killed"
  // for a valid owner session, or 401 for an invalid one. Neither mutates
  // state, so this proves the token works before any kill is engaged.
  const probe = await restoreProbe(
    baseUrl,
    ownerToken,
    { ceremonyId: "verify-probe", ownerId: AGENT_ID, completedAt: now() },
    fetchImpl,
  );
  if (probe.status === 401) {
    return fail(
      "owner token",
      "control plane rejected the owner token (401) — get a fresh one and re-run with --owner-token",
    );
  }
  if (probe.status !== 409) {
    return fail(
      "owner token",
      `unexpected HTTP ${probe.status} validating the owner token (${probe.error ?? "no detail"})`,
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

  const killBody = JSON.stringify({ reason: "ownerswitch-mcp verify preflight check", source: "api" });
  let killEngaged = false;
  try {
    const res = await deviceSignedPost(baseUrl, "/kill", config.device, killBody, fetchImpl, now);
    if (!res.ok) throw new Error(`control plane refused kill (HTTP ${res.status})`);
    killEngaged = true;
  } catch (err) {
    steps.push({
      name: "kill switch",
      ok: false,
      detail: `could not engage the kill switch to test it: ${errorMessage(err)} (system state unchanged)`,
    });
    return { steps, ok: false };
  }

  const afterKillStatus = await getStatus(baseUrl, fetchImpl);
  const killConfirmed = afterKillStatus.ok && afterKillStatus.killed;
  let refusalConfirmed: boolean | undefined;
  if (allowCall !== undefined) {
    refusalConfirmed = decisionFor(allowCall, policy, killConfirmed) === "deny";
  }

  steps.push({
    name: "kill switch",
    ok: killConfirmed && (refusalConfirmed ?? true),
    detail: !killConfirmed
      ? `engaged, but /status still does not report killed:true`
      : allowCall === undefined
        ? "engaged — /status now reports killed:true"
        : refusalConfirmed
          ? `engaged — "${allowCall.tool}" (previously allowed) is now refused`
          : `engaged, but "${allowCall.tool}" was still evaluated as allowed — enforcement is NOT fail-closed`,
  });

  // Always attempt restore once a kill was engaged, regardless of the checks
  // above — leaving the system killed is the one outcome verify must avoid.
  const ceremonyId = `verify-${randomBytes(6).toString("hex")}`;
  const restoreResult = await restoreProbe(
    baseUrl,
    ownerToken,
    { ceremonyId, ownerId: AGENT_ID, completedAt: now() },
    fetchImpl,
  );
  const restoredOk = restoreResult.status === 200;
  const finalStatus = restoredOk ? await getStatus(baseUrl, fetchImpl) : undefined;
  const restored = restoredOk && finalStatus?.ok === true && !finalStatus.killed;

  steps.push({
    name: "restore",
    ok: restored,
    detail: restored
      ? "system restored to its starting state (killed:false)"
      : `FAILED to restore — the kill switch is still ENGAGED (HTTP ${restoreResult.status}${
          restoreResult.error ? `: ${restoreResult.error}` : ""
        }). Restore it manually: POST ${baseUrl}/restore with a valid owner session, e.g. ` +
        `curl -X POST ${baseUrl}/restore -H 'Authorization: Bearer <owner token>' ` +
        `-d '{"ceremonyId":"manual-1","ownerId":"you","completedAt":${now()}}' ` +
        `— or, if this is the dev control plane, just restart it (state is in-memory).`,
  });

  return { steps, ok: steps.every((s) => s.ok) };
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

export function extractOwnerToken(
  argv: string[],
  env: Record<string, string | undefined>,
): { ownerToken?: string; rest: string[] } {
  const rest: string[] = [];
  let ownerToken: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--owner-token") {
      ownerToken = argv[i + 1];
      i++;
    } else if (arg.startsWith("--owner-token=")) {
      ownerToken = arg.slice("--owner-token=".length);
    } else {
      rest.push(arg);
    }
  }
  return { ownerToken: ownerToken ?? env.OWNERSWITCH_OWNER_TOKEN, rest };
}

/** CLI entry point for `ownerswitch-mcp verify`. Returns the process exit code. */
export async function verifyMain(argv: string[], env: Record<string, string | undefined>): Promise<number> {
  const { ownerToken, rest } = extractOwnerToken(argv, env);
  let config: OwnerSwitchMcpConfig;
  try {
    config = loadConfig(rest, env);
  } catch (err) {
    console.error(`[ownerswitch-mcp verify] config error: ${err instanceof ConfigError ? err.message : errorMessage(err)}`);
    return 1;
  }
  const outcome = await runVerify(config, ownerToken);
  console.log(formatVerifyReport(outcome));
  return outcome.ok ? 0 : 1;
}
