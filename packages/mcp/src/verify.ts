/**
 * `ownerswitch-mcp verify` — proves enforcement works before any agent is
 * involved, without ever touching the global kill switch.
 *
 * It exercises the exact decision path the gateway uses at runtime
 * (evaluate(), the same function proxy.ts calls) plus the real veto lane end
 * to end, against the live control plane:
 *   - a call the policy allows → allowed
 *   - a call matching no rule → the fail-closed default
 *   - a veto-lane round trip: register a real window (device-signed), veto it
 *     as the owner (bearer token), confirm it reads back "vetoed" — the
 *     owner's one tap, demonstrated live. A vetoed window is terminal and
 *     inert; nothing is left pending in front of an owner and no upstream
 *     tool ever runs.
 *
 * A full kill/restore cycle is deliberately NOT part of this preflight: a
 * live kill/restore round trip from a CLI has real distributed-systems edges
 * (ambiguous completion on a network blip mid-kill, a lost connection right
 * before confirming restore, a Ctrl-C mid-ceremony) that a DX check has no
 * business improvising answers to. That coverage already exists at the layer
 * that owns it — control-plane/src/integration.test.ts (kill -> 2GO ->
 * restore) and the ceremony's HTTP-level tests in
 * control-plane/src/server.test.ts — so verify doesn't repeat it here; it
 * stays a fast, side-effect-light preflight.
 *
 * If a lane genuinely can't be exercised (e.g. the policy has no "allow"
 * rule to build a demonstration call from), that is reported as a FAILURE
 * naming what's missing — never folded into an overall PASS. verify proves
 * three specific things; if it can't prove one, it says so and fails.
 *
 * The owner token comes from OWNERSWITCH_OWNER_TOKEN or an interactive,
 * echo-suppressed prompt — never a CLI flag, which would leak it into shell
 * history and process listings. It is validated up front via a harmless
 * POST /restore probe (an unmintable ceremony id: 409 "restore rejected"
 * proves the token is accepted, 401 proves it is not, and neither mutates
 * anything).
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
    // /status is live security state — never accept a cached answer
    const res = await fetchImpl(new URL("/status", baseUrl), { cache: "no-store" });
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

/** The exact commands to un-kill a plane via the real 2GO ceremony. */
function recoveryInstructions(baseUrl: string): string {
  return [
    `Restore it with the 2GO ceremony (restarting the control plane does NOT restore it — kill state persists to disk):`,
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
  if (allowRule === undefined) {
    steps.push({
      name: "allow call",
      ok: false,
      detail: `cannot prove "allow" — this policy has no rule with decision "allow" to build a demonstration call from`,
    });
  } else {
    const allowCall: ToolCall = { agentId: AGENT_ID, tool: probeToolFor(allowRule.tool) };
    const decision = decisionFor(allowCall, policy, false);
    steps.push({
      name: "allow call",
      ok: decision === "allow",
      detail:
        decision === "allow"
          ? `"${allowCall.tool}" (rule "${allowRule.id}") → allowed, as configured`
          : `"${allowCall.tool}" (rule "${allowRule.id}") → expected "allow", got "${decision}"`,
    });
  }

  const defaultCall: ToolCall = { agentId: AGENT_ID, tool: DEFAULT_PROBE_TOOL };
  const defaultVerdict = evaluate(defaultCall, policy, { killed: false });
  if (defaultVerdict.ruleId !== null) {
    steps.push({
      name: "default decision",
      ok: false,
      detail:
        `cannot prove the fail-closed default — every tool name matches an explicit rule in this ` +
        `policy (e.g. a catch-all "*"), so no call ever reaches defaultDecision`,
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

  // The veto lane, end to end: register a real window as the gateway would
  // (device-signed), stop it with the owner's one tap, and read the terminal
  // state back. Proves device credentials, the owner token's authority, and
  // that a vetoed call STAYS vetoed. Unlike the two checks above this always
  // performs real work — there is no "can't be exercised" case — so its
  // pass/fail reflects a genuine live round trip either way. The residue is
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

  return { steps, ok: steps.every((s) => s.ok) };
}

export function formatVerifyReport(outcome: VerifyOutcome): string {
  const lines = outcome.steps.map((s) => `${s.ok ? "✔" : "✘"} ${s.name} — ${s.detail}`);
  lines.push("");
  lines.push(
    outcome.ok
      ? "PASS — enforcement is working. Safe to point an agent at this gateway."
      : "FAIL — do not connect an agent yet.",
  );
  return lines.join("\n");
}

/**
 * Minimal shape of the streams readHiddenLine needs — matches
 * process.stdin/process.stdout, kept narrow so tests can pass plain fakes
 * instead of real TTYs.
 */
export interface HiddenLineInput {
  isTTY?: boolean;
  isRaw?: boolean;
  setRawMode?: (mode: boolean) => unknown;
  setEncoding?: (encoding: BufferEncoding) => unknown;
  resume: () => unknown;
  pause: () => unknown;
  on: (event: "data", listener: (chunk: string) => void) => unknown;
  removeListener: (event: "data", listener: (chunk: string) => void) => unknown;
}
export interface HiddenLineOutput {
  write: (chunk: string) => void;
}

/**
 * Reads one line from `input` without ever echoing the typed characters to
 * `output` — raw mode disables the terminal's own echo, and this function
 * writes nothing back except the literal prompt and a trailing newline once
 * the user presses Enter. Used for the owner-token prompt so a pasted token
 * never lands in terminal scrollback or a captured recording.
 */
export async function readHiddenLine(
  promptText: string,
  input: HiddenLineInput,
  output: HiddenLineOutput,
): Promise<string | undefined> {
  output.write(promptText);
  const wasRaw = input.isRaw ?? false;
  input.setEncoding?.("utf8");
  input.setRawMode?.(true);
  input.resume();

  // Control characters compared by code point, not string literals — a raw
  // control byte in source is invisible and easy to corrupt in transit; a
  // numeric comparison against a named constant isn't.
  const ENTER_CODES = new Set([10, 13]); // \n, \r
  const CTRL_C_CODE = 3; // ETX
  const BACKSPACE_CODES = new Set([8, 127]); // BS, DEL

  return new Promise((resolve) => {
    let value = "";
    const onData = (chunk: string): void => {
      for (const char of chunk) {
        const code = char.codePointAt(0);
        if (code !== undefined && ENTER_CODES.has(code)) {
          cleanup();
          output.write("\n");
          resolve(value === "" ? undefined : value);
          return;
        }
        if (code === CTRL_C_CODE) {
          // Raw mode suppresses the terminal's own SIGINT generation, so
          // this is the only place Ctrl-C can be handled — restore the
          // terminal and exit the same way an uncaught SIGINT would.
          cleanup();
          output.write("\n");
          process.exit(130);
          return;
        }
        if (code !== undefined && BACKSPACE_CODES.has(code)) {
          value = value.slice(0, -1);
          continue;
        }
        value += char;
      }
    };
    const cleanup = (): void => {
      input.removeListener("data", onData);
      input.setRawMode?.(wasRaw);
      input.pause();
    };
    input.on("data", onData);
  });
}

/**
 * The owner token, from the environment or an interactive, echo-suppressed
 * prompt — never argv, which `ps` and shell history record.
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
  const trimmed = (
    await readHiddenLine("Owner token (printed by the control plane at startup): ", process.stdin, process.stdout)
  )?.trim();
  return trimmed === undefined || trimmed === "" ? undefined : trimmed;
}

/** CLI entry point for `ownerswitch-mcp verify`. Returns the process exit code. */
export async function verifyMain(argv: string[], env: Record<string, string | undefined>): Promise<number> {
  const rest: string[] = [];
  for (const arg of argv) {
    if (arg === "--owner-token" || arg.startsWith("--owner-token=")) {
      console.error(
        "[ownerswitch-mcp verify] --owner-token was removed: a token on the command line leaks into " +
          "shell history and process listings. Set OWNERSWITCH_OWNER_TOKEN, or run verify in a " +
          "terminal and paste the token at the prompt.",
      );
      return 1;
    }
    rest.push(arg);
  }
  let config: OwnerSwitchMcpConfig;
  try {
    config = loadConfig(rest, env);
  } catch (err) {
    console.error(`[ownerswitch-mcp verify] config error: ${err instanceof ConfigError ? err.message : errorMessage(err)}`);
    return 1;
  }
  const ownerToken = await resolveOwnerToken(env);
  const outcome = await runVerify(config, ownerToken);
  console.log(formatVerifyReport(outcome));
  return outcome.ok ? 0 : 1;
}
