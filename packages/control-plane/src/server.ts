import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { statSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import {
  buildRenderableApproval,
  canonicalJson,
  GITHUB_CONNECTOR,
  MERGE_PULL_REQUEST,
  parseMergePrArgs,
  sha256Hex,
  signMergeGrant,
  type SignedMergeGrant,
  type ToolCall,
} from "@ownerswitchai/shared";
import {
  createOwnerSession,
  isLoopbackAddress,
  verifyDeviceSignature,
  verifyOwnerSession,
  type DeviceCredential,
  type OwnerSession,
} from "./auth.js";
import { KillStateFileStore } from "./kill-state.js";
import { KILL_SOURCES, KillSwitch, type KillSource } from "./kill.js";
import { verifyLicense } from "./license.js";
import { RestoreCeremony } from "./twogo.js";
import { VetoWindow, type VetoPurpose, type VetoWireStatus } from "./veto.js";
import { verifyOwnerAssertion, type WebAuthnAssertion } from "./webauthn.js";

/**
 * HTTP layer of the control plane. One process, one KillSwitch, one map of
 * live veto windows — the gateway, the owner app and the physical button all
 * talk to the same state through this handler.
 *
 * Deliberately framework-free: Node's http module only, so the surface stays
 * small enough to audit in one sitting.
 *
 * Auth keeps the asymmetry of the switch itself:
 *  - POST /kill     — a device signature or owner session attributes the kill;
 *                     with neither, loopback callers may still kill (recorded
 *                     as an unauthenticated "api" kill). Stopping must never
 *                     fail because auth was misconfigured.
 *  - POST /alert    — a flagged event that does NOT change kill state (a
 *                     honeytoken FILE was touched). Same auth shape as /kill;
 *                     recorded in the audit log, never a lockdown.
 *  - POST /restore/ceremony     — owner session required; starts 2GO (GO 1/2)
 *                     while the system is killed. The ceremony binds to the
 *                     owner, the kill epoch in force, and its start time. An
 *                     owner holds at most ONE live ceremony per kill epoch,
 *                     and GO 1/2 is IDEMPOTENT: while one is pending, a
 *                     repeat call returns that same ceremony (200) with its
 *                     clocks untouched — a retry or second tab cannot
 *                     invalidate the id the owner holds, and a stolen
 *                     same-owner session cannot reset the cooldown.
 *                     There is deliberately NO cancel verb: a pending
 *                     ceremony ends only by TTL expiry, consumption, or a
 *                     new kill epoch. A cancel would hand the same bearer
 *                     token a repeatable way to destroy the owner's pending
 *                     ceremony — the exact lockout idempotency closes.
 *  - GET  /restore/ceremony/:id — owner session required; the ceremony's
 *                     state, cooldown remaining, and expiry.
 *  - POST /restore/ceremony/:id/challenge — owner session required; with a
 *                     passkey enrolled, mints the single-use GO 2/2 assertion
 *                     challenge (bound to {ceremonyId, killEpoch}) the owner
 *                     signs to complete a restore. 501 in a dev instance with
 *                     no passkey, where GO 2/2 stays session-only.
 *  - POST /restore  — owner session required plus a live server-side ceremony
 *                     (GO 2/2): owned by this owner, past its cooldown, inside
 *                     its TTL, bound to the current kill epoch, consumed
 *                     atomically (single-spend holds for this one process and
 *                     event loop — where all ceremony state lives). With a
 *                     passkey enrolled it ALSO requires a fresh single-use
 *                     WebAuthn assertion over that challenge — a stolen owner
 *                     session alone cannot restore. No exceptions, no loopback
 *                     bypass, no shape-only path.
 *  - POST /veto     — device signature required; a gateway registers a window
 *                     for a call it is holding. Registration puts text in
 *                     front of the owner and grows server state, so unlike
 *                     /kill there is no loopback fallback: a gateway that
 *                     cannot register must fail its call closed, not get an
 *                     open door here.
 *  - POST /veto/:id — owner session (the session names the vetoer, and only
 *                     a session may approve) OR device signature (deny-only:
 *                     the escalation ladder's relayed channel stops and the
 *                     owner app's one-tap veto; idempotent on re-veto).
 *  - POST /veto/:id/seen — OWNER-APP signature required (ownerAppSecret, a
 *                     distinct credential from the fleet deviceSecret — this
 *                     is the permissive delivered bit, so no fleet component
 *                     or same-uid agent may forge it); 501 when no owner-app
 *                     secret is enrolled. The production caller of
 *                     markDelivered(). Refused inside the 60 s response floor
 *                     before the deadline (MIN_VETO_RESPONSE_MS).
 *  - GET  /veto/pending — device signature required; the open-window listing
 *                     the escalation ladder polls, with deadlines and
 *                     delivered bits.
 *  - GET  /veto/:id — open read is status-only; a device-signed read adds
 *                     `deadline` and `delivered` so escalation paces itself
 *                     off the window's own clock.
 *  - GET  /status   — open; the gateway polls it. Body carries `killed` and
 *                     the kill `epoch` (a monotone count of every kill this
 *                     deployment has ever had) — the deliberate, documented
 *                     widening of what this open route leaks; see getStatus()
 *                     below and packages/mcp/THREAT-MODEL.md.
 */
export interface ControlPlaneOptions {
  now?: () => number;
  /** Shared secret the physical button / kill triggers sign requests with. */
  deviceSecret?: string;
  /**
   * The OWNER APP's OWN device secret — a DISTINCT credential from
   * `deviceSecret`, provisioned only to the enrolled owner app and held by
   * nothing else (not the gateway, not the button, not the escalation
   * service). It authenticates exactly one thing: the delivery ack
   * (`POST /veto/:id/seen`), which flips the permissive `delivered` bit that
   * lets silence RELEASE a window (veto.ts). That bit is the one place the
   * veto lane trusts a device to speak for the owner, so it must not ride
   * the fleet-wide `deviceSecret` — under the same-uid threat model an agent
   * can forge that (packages/mcp/THREAT-MODEL.md), and forging the ack would
   * silently convert "held, owner-gated" into "released, runs" while also
   * standing the escalation ladder down. Absent → `/veto/:id/seen` is 501 and
   * delivery confirmation stays UNWIRED: every untouched window walks
   * pending → extended → held → passkey approval, the fail-closed default
   * (exactly the pre-escalation behavior). The deny-only device endpoints
   * (`/kill`, the veto relay, `/veto/pending`, the pacing read) keep using
   * `deviceSecret`: their worst case is a stop, so a forged one is safe.
   */
  ownerAppSecret?: string;
  /**
   * Where the kill switch persists killed state, its reason and the kill
   * epoch across process restarts.
   *
   * In production (the default), this is REQUIRED and checked at boot: it
   * must be an explicit absolute path outside the working directory, in a
   * directory owned by the process user with no group/world write access.
   * Anything else refuses to start — whoever can write this directory holds
   * an administrative capability over kill state.
   *
   * With dev: true, it defaults to DEFAULT_KILL_STATE_FILE in the working
   * directory, and null runs a deliberately ephemeral control plane (unit
   * tests, throwaway demos): a restart then forgets the kill, so only opt
   * out where that is the point.
   */
  killStateFile?: string | null;
  /**
   * Development mode: skips the kill-state path safety checks (with a loud
   * one-line warning) and enables the conveniences above. Never set this for
   * a control plane that real agents depend on.
   */
  dev?: boolean;
  /**
   * The HMAC key the control plane and the executing merge broker share to
   * authorize merges (`packages/shared/src/merge-grant.ts`,
   * `packages/executor/src/merge-broker.ts`). When set, a veto window that
   * RELEASES while its kill epoch is still current — and that was
   * REGISTERED under the grant-eligible purpose (github/merge_pull_request,
   * with arguments that parse under the closed merge schema) — mints a
   * single-use, signed MergeGrant over the exact call the owner reviewed:
   * the broker's only proof that a merge was approved by the owner and not
   * merely requested by an agent sharing the gateway's uid. A window
   * registered under any other purpose (or none) releases normally but is
   * never grant-eligible. Provision the key ONLY to the control plane and
   * the broker, never to the gateway/agent environment (that is the whole
   * point — the gateway REFUSES to start if it sees the key, and this
   * process needs the same uid/host isolation from the agent as the broker,
   * or the key is readable and grants forgeable). Absent → no grants are
   * minted and the executing-broker path cannot be used (the proxy-only and
   * same-process deployments are unaffected).
   */
  grantKey?: string;
  /**
   * MergeGrant lifetime in ms, measured FROM THE APPROVAL MOMENT (the
   * owner's active approval), not from whenever the grant is first
   * fetched; default 2 min (minutes, not hours). An approval that sits
   * unread past this window is served "spent" — it never becomes a fresh
   * capability later.
   */
  grantTtlMs?: number;
  /**
   * The HMAC key that AUTHENTICATES the broker's live kill-state channel
   * (`GET /kill-state`). When set, the control plane answers a
   * nonce-carrying kill-state request with a SIGNED envelope the broker
   * verifies against the same key — so a hostile local process that binds
   * this port after the real control plane stops cannot answer
   * `{killed:false}` and defeat the broker's fail-closed check. Distinct
   * from the grant key (different job, different blast radius) and shared
   * ONLY with the broker. Absent → `/kill-state` is 501 and the broker
   * must fall back to `/status`, which is unauthenticated.
   */
  killStateKey?: string;
  /**
   * The owner's enrolled APPROVAL PASSKEY. When set, an active approval of
   * a grant-eligible (merge) window requires a fresh WebAuthn assertion —
   * minted challenge, bound to {windowId, callHash}, single-use, UP+UV,
   * counter-checked (webauthn.ts) — ON TOP of the owner session. An owner
   * session alone is a reusable bearer token; a stolen one must not mint
   * merge authority. Enrollment (credential id + SPKI public key + rpId,
   * optionally the exact origin) happens in the owner app at provisioning
   * time, the same trust step as the device secret. When ABSENT, approvals
   * fall back to session-only ONLY in dev mode; a non-dev control plane
   * with a grant key but no passkey refuses approvals outright.
   */
  ownerPasskey?: {
    credentialId: string;
    publicKeyPem: string;
    rpId: string;
    /**
     * The exact origin the owner app runs at (e.g. https://owner.example) —
     * REQUIRED, and https:// outside dev. WebAuthn's phishing resistance is
     * the origin binding, so it is not optional; the control plane refuses
     * to start with an enrolled passkey and no (or a non-https) origin.
     */
    origin: string;
  };
  /**
   * Explicit acknowledgment that this DEV control plane mints merge grants
   * on a SESSION-ONLY approval (a reusable bearer token), with no passkey.
   * Required to start a dev control plane that has a grant key but no
   * `ownerPasskey` — otherwise it refuses, so a session-only approval
   * boundary is never reached by accident. Ignored in production (where a
   * passkey is mandatory) and irrelevant without a grant key.
   */
  acceptSessionOnlyApprovalRisk?: boolean;
  /**
   * Commercial licensing for 2GO — the ONE license-aware point in the whole
   * system, and it gates exactly one thing: STARTING a restore ceremony
   * (POST /restore/ceremony → 402 without a valid license). The doctrine
   * lives in license.ts and is worth restating at the option: no deny-path
   * — kill, veto, ack, status, the escalation ladder — ever consults this;
   * stopping is free forever. Expired licenses keep restoring for the 72 h
   * anti-ransom grace, and an unlicensed plane still STOPS perfectly — it
   * just cannot be turned back on through 2GO until licensed. When this
   * option is absent (the default, and every dev/quickstart instance),
   * ceremonies are ungated — the private-beta behavior.
   */
  licensing?: {
    /** the vendor's Ed25519 SPKI PEM that license tokens verify against */
    vendorPublicKeyPem: string;
    /** the deployment's OWNERSWITCH_LICENSE token; absent = unlicensed */
    token?: string;
    /**
     * This deployment's immutable id (OWNERSWITCH_DEPLOYMENT_ID — the same
     * one the honeytoken registry pins). A license minted with a
     * deploymentId verifies only where the ids match, so a stolen token
     * licenses nothing anywhere else (license.ts, theft containment).
     */
    deploymentId?: string;
  };
}

/** Default kill-state location IN DEV MODE, resolved against the working directory. */
export const DEFAULT_KILL_STATE_FILE = "ownerswitch-kill-state.json";

/**
 * Production boot guard for the kill-state path. Every refusal says exactly
 * what is wrong and what the operator must do — a control plane that starts
 * with a tamperable state file is worse than one that refuses to start.
 */
function guardKillStatePath(file: string | null | undefined): string {
  const refuse = (what: string, fix: string): never => {
    const msg = `[ownerswitch] refusing to start: ${what}. ${fix} (Pass dev: true only for a development instance.)`;
    console.error(msg);
    throw new Error(msg);
  };
  if (file === undefined) {
    return refuse(
      "no killStateFile configured",
      "Set killStateFile to an explicit absolute path in a protected directory, e.g. /var/lib/ownerswitch/kill-state.json.",
    );
  }
  if (file === null) {
    return refuse(
      "killStateFile: null (ephemeral) is a development convenience",
      "An ephemeral control plane forgets kills on restart. Set an absolute killStateFile.",
    );
  }
  if (!isAbsolute(file)) {
    return refuse(
      `killStateFile "${file}" is a relative path`,
      "Set an explicit absolute path — a relative path silently points at a different store whenever the working directory changes.",
    );
  }
  const resolved = resolve(file);
  const rel = relative(process.cwd(), resolved);
  if (rel === "" || (!rel.startsWith("..") && !isAbsolute(rel))) {
    return refuse(
      `killStateFile "${resolved}" resolves inside the working directory ${process.cwd()}`,
      "The working directory is not a protected location. Put the state file in a dedicated directory such as /var/lib/ownerswitch/.",
    );
  }
  const dir = dirname(resolved);
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  let stats;
  try {
    stats = statSync(dir);
  } catch (err) {
    return refuse(
      `the kill-state directory ${dir} cannot be inspected (${err instanceof Error ? err.message : String(err)})`,
      `Create it first, owned by uid ${uid ?? "<process uid>"} with mode 0700: mkdir -p ${dir} && chmod 700 ${dir}.`,
    );
  }
  if (!stats.isDirectory()) {
    return refuse(`${dir} is not a directory`, "Point killStateFile at a file inside a real, protected directory.");
  }
  if ((stats.mode & 0o022) !== 0) {
    return refuse(
      `the kill-state directory ${dir} is group- or world-writable (mode ${(stats.mode & 0o777).toString(8)})`,
      `Anyone who can write this directory can tamper with kill state. Run: chmod 700 ${dir}.`,
    );
  }
  // POSIX-only check: without getuid (Windows) ownership cannot be compared.
  if (uid !== undefined && stats.uid !== uid) {
    return refuse(
      `the kill-state directory ${dir} is owned by uid ${stats.uid}, but the control plane runs as uid ${uid}`,
      `The directory must belong to the user that runs the control plane. Run: chown ${uid} ${dir}.`,
    );
  }
  return resolved;
}

export interface ControlPlane {
  /** Plug into http.createServer(handler). */
  handler: (req: IncomingMessage, res: ServerResponse) => void;
  killSwitch: KillSwitch;
  /** Live veto windows by id; the gateway registers, the API vetoes/reads. */
  vetoWindows: Map<string, VetoWindow>;
}

/**
 * Hard ceiling on ceremony RECORDS held in memory — a memory backstop, not a
 * rate limit and never the primary bound. Before it is consulted, every dead
 * record (TTL-expired, consumed, superseded kill epoch) is purged and each
 * owner is limited to one live ceremony per kill epoch, so the map's size is
 * the number of DISTINCT owners with a pending ceremony: normal use is 1–2.
 * The ceiling only stops a flood of hostile owner sessions from growing the
 * map without bound, which is why it sits far above any legitimate count.
 */
export const MAX_CEREMONY_RECORDS = 256;

/**
 * The minimum time the owner must have between an accepted delivery ack and
 * the deadline it would let silence spend (apps/owner/DESIGN.md §3): an ack
 * that lands closer than this is refused, so the window extends or holds on
 * its own clock instead of releasing an action the owner had no real chance
 * to veto. A floor, not a knob to zero out.
 */
export const MIN_VETO_RESPONSE_MS = 60_000;

/** Thrown when the request body is not valid JSON — maps to 400. */
class BadJsonError extends Error {}

async function readRawBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

function parseJsonBody(raw: string): Record<string, unknown> {
  const trimmed = raw.trim();
  if (trimmed === "") return {}; // empty body is fine — stopping must never fail on a technicality
  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new BadJsonError("body must be a JSON object");
    }
    return parsed as Record<string, unknown>;
  } catch (err) {
    if (err instanceof BadJsonError) throw err;
    throw new BadJsonError("malformed JSON body");
  }
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  // NOTHING this server serves is cacheable. Every response is live security
  // state — kill state and epoch on /status, window status on /veto/:id,
  // ceremony state — and a reverse proxy or intermediate cache replaying a
  // stale {killed:false, epoch:N} or "released" after a kill would defeat
  // the exact checks that state exists for (the executor's live re-checks,
  // the window-epoch binding). no-store on EVERY response, plus Pragma for
  // legacy intermediaries; the deployment requirement — no cache may sit in
  // front of the control plane — is stated in packages/mcp/THREAT-MODEL.md.
  res.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store, max-age=0",
    pragma: "no-cache",
  });
  res.end(JSON.stringify(body));
}

/** 401s stay generic: an unauthenticated caller learns nothing about the domain. */
function sendUnauthorized(res: ServerResponse): void {
  sendJson(res, 401, { error: "unauthorized" });
}

function headerValue(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name];
  return Array.isArray(value) ? value[0] : value;
}

/** All four x-device-* headers, or null when the request doesn't attempt device auth. */
function deviceCredentialFrom(req: IncomingMessage): DeviceCredential | null {
  const deviceId = headerValue(req, "x-device-id");
  const timestamp = headerValue(req, "x-device-timestamp");
  const nonce = headerValue(req, "x-device-nonce");
  const signature = headerValue(req, "x-device-signature");
  if (!deviceId || !timestamp || !nonce || !signature) return null;
  return { deviceId, timestamp: Number(timestamp), nonce, signature };
}

function bearerToken(req: IncomingMessage): string | null {
  // the auth-scheme is case-insensitive (RFC 9110 §11.1); the token is not
  const match = /^Bearer (.+)$/i.exec(headerValue(req, "authorization") ?? "");
  return match ? match[1] : null;
}

export function createControlPlane(opts: ControlPlaneOptions = {}): ControlPlane {
  const now = opts.now ?? Date.now;
  // Persisted kill state loads synchronously inside the KillSwitch
  // constructor — before this function returns a handler, so before any
  // request can be answered. A process restart resumes the kill state it
  // went down with (`kill -9` is not a restore), and a state file that
  // exists but cannot be read boots the plane killed. In production the
  // path is guarded first: a state file an attacker can write is not
  // persistence, so a bad location refuses to start.
  let killStateFile: string | undefined;
  if (opts.dev === true) {
    console.error(
      "[ownerswitch] DEV MODE: kill-state path safety checks are disabled — never point production agents at this control plane.",
    );
    killStateFile =
      opts.killStateFile === null
        ? undefined
        : (opts.killStateFile ?? resolve(process.cwd(), DEFAULT_KILL_STATE_FILE));
  } else {
    killStateFile = guardKillStatePath(opts.killStateFile);
  }
  // A merge-authorizing HMAC key must carry real entropy: whoever holds it
  // mints owner approvals. Refuse a weak one at startup rather than sign
  // with it. (The kill-state key gets the same floor.)
  if (opts.grantKey !== undefined && opts.grantKey !== "" && Buffer.byteLength(opts.grantKey, "utf8") < 32) {
    throw new Error(
      "OWNERSWITCH_GRANT_KEY is under 32 bytes — a merge-authorizing HMAC key must carry at " +
        "least 256 bits of secret; generate one with `openssl rand -hex 32`",
    );
  }
  if (
    opts.killStateKey !== undefined &&
    opts.killStateKey !== "" &&
    Buffer.byteLength(opts.killStateKey, "utf8") < 32
  ) {
    throw new Error(
      "OWNERSWITCH_KILL_STATE_KEY is under 32 bytes — it authenticates the kill-state channel " +
        "and must carry at least 256 bits of secret; generate one with `openssl rand -hex 32`",
    );
  }
  // An enrolled approval passkey needs an exact origin — https:// outside
  // dev — because WebAuthn's phishing resistance IS the origin binding.
  if (opts.ownerPasskey !== undefined) {
    const origin = opts.ownerPasskey.origin;
    if (typeof origin !== "string" || origin === "") {
      throw new Error(
        "ownerPasskey.origin is required — WebAuthn assertion verification must bind the exact " +
          "origin the owner app runs at (e.g. https://owner.example)",
      );
    }
    if (opts.dev !== true && !origin.startsWith("https://")) {
      throw new Error(
        `ownerPasskey.origin must be https:// in production, got "${origin}" — an http origin ` +
          "defeats the phishing-resistance the passkey provides",
      );
    }
  }
  // A control plane that mints merge grants but has no passkey approves on a
  // reusable bearer session — the weaker boundary. In production that path
  // is simply refused (the approve handler returns 403). In DEV it stays
  // available for the quickstart, but only behind an explicit written
  // acknowledgment, so it is never reached by accident.
  const grantsWithoutPasskey =
    opts.grantKey !== undefined && opts.grantKey !== "" && opts.ownerPasskey === undefined;
  if (grantsWithoutPasskey && opts.dev === true && opts.acceptSessionOnlyApprovalRisk !== true) {
    throw new Error(
      "this control plane has a grant key but no enrolled ownerPasskey, so it would approve " +
        "merges on a reusable owner SESSION alone. In dev that requires " +
        "acceptSessionOnlyApprovalRisk: true (env OWNERSWITCH_ACCEPT_SESSION_ONLY_APPROVAL_RISK=1); " +
        "in production, enroll a passkey instead.",
    );
  }
  // Licensing never stops a boot and never touches a stop path — but a
  // plane whose restores WILL be refused should say so at startup, not
  // during the incident. (license.ts holds the doctrine.)
  if (opts.licensing !== undefined) {
    const verdict = verifyLicense(
      opts.licensing.token ?? "",
      opts.licensing.vendorPublicKeyPem,
      now(),
      opts.licensing.deploymentId,
    );
    if (!verdict.ok) {
      console.error(
        `[ownerswitch] UNLICENSED for 2GO restore: ${verdict.reason} — the kill switch, vetoes and ` +
          "all stop paths run free and unaffected; POST /restore/ceremony will answer 402 until licensed.",
      );
    } else if (verdict.state === "grace") {
      console.error(
        `[ownerswitch] license for "${verdict.license.licensee}" is EXPIRED and inside the 72 h ` +
          "restore grace — renew now; restores stop working when the grace ends.",
      );
    } else if (verdict.license.expiresAt - now() < 14 * 86_400_000) {
      console.error(
        `[ownerswitch] license for "${verdict.license.licensee}" expires ` +
          `${new Date(verdict.license.expiresAt).toISOString()} — renew soon.`,
      );
    }
  }
  const killSwitch = new KillSwitch(
    now,
    killStateFile === undefined ? {} : { store: new KillStateFileStore(killStateFile) },
  );
  const vetoWindows = new Map<string, VetoWindow>();
  const seenNonces = new Map<string, number>();
  // Window ids whose single-use MergeGrant has already been minted. A window
  // authorizes exactly ONE merge: the first releasing read mints the grant
  // and records the id here; every later read of the same window is served
  // "spent". This is where single-use burns on the control-plane side —
  // outside the agent's reach, authoritative, and it survives whatever the
  // window record survives.
  const grantedWindows = new Set<string>();
  // Minted grant jtis → their window ids, for the broker's grant-liveness
  // probe: the broker refuses a merge unless this control plane SIGNS that
  // it minted the grant and its window is not vetoed. Deliberately
  // process-local: a restart forgets outstanding grants, which fails
  // CLOSED — a grant this plane cannot vouch for does not dispatch.
  const mintedGrants = new Map<string, string>();
  // Reverse of mintedGrants for the veto path: a window id → its grant jti,
  // so a veto can tell whether the grant is already committed for dispatch.
  const windowToGrant = new Map<string, string>();
  // Grants the broker has ATOMICALLY committed for dispatch. Once a jti is
  // here, a merge is in flight and a later veto is too late; before it is
  // here, a veto still revokes. The commit handler and the veto handler are
  // the only writers, both synchronous, so they cannot interleave — the
  // race has exactly one winner.
  const committedGrants = new Set<string>();
  const grantTtlMs = opts.grantTtlMs ?? 2 * 60_000;
  // How long a broker's signed commit request may be in flight before the
  // control plane rejects it as stale (replay bound).
  const COMMIT_REQUEST_SKEW_MS = 30_000;
  // Outstanding approval ceremonies, one per window: the server-minted
  // challenge the owner's passkey must sign, bound to the exact call
  // (callHash) it would approve. Redeemed ATOMICALLY (deleted before
  // verification) so each challenge is spent by its first use, valid or
  // not. Process-local: a restart voids outstanding ceremonies — the owner
  // requests a fresh one, which only they can complete anyway.
  const approvalChallenges = new Map<
    string,
    { challenge: string; callHash: string; renderHash: string; killEpoch: number; expiresAt: number }
  >();
  const APPROVAL_CHALLENGE_TTL_MS = 2 * 60_000;
  // last accepted signature counter for the enrolled passkey (clone signal)
  let passkeySignCount = 0;
  // Outstanding passkey LOGIN challenges (challenge → {expiry, kill epoch}),
  // single-use. These bootstrap an owner SESSION: a fresh production process
  // has no way to mint one otherwise, yet both approval endpoints need an
  // owner session. The challenge is worthless without the enrolled passkey to
  // sign it, so minting one is a harmless open operation; the session is
  // handed out only after a verified assertion. The kill epoch is stamped at
  // mint time (after the body drains) and required to still match at
  // redemption: a challenge that spanned a KILL is dead, so one stalled
  // across the kill boundary cannot be redeemed into the post-restore world.
  const loginChallenges = new Map<string, { expiresAt: number; killEpoch: number }>();
  const LOGIN_CHALLENGE_TTL_MS = 2 * 60_000;
  // Cap on pending login challenges: minting one is unauthenticated (only a
  // passkey holder can REDEEM one, but anyone can ask), so bound the map so a
  // flood cannot exhaust memory. Well past any honest concurrent-login count.
  const MAX_LOGIN_CHALLENGES = 256;
  // Live restore ceremonies, keyed by id. Deliberately process-local: losing
  // this map (a restart) can only make restores harder, never easier — an id
  // that is not in here restores nothing, whatever its body claims.
  const ceremonies = new Map<string, { ceremony: RestoreCeremony; epoch: number }>();
  // Outstanding GO 2/2 restore assertion challenges, keyed by ceremony id: the
  // server-minted challenge the owner's passkey must sign to complete a
  // restore, bound to {ceremonyId, killEpoch}. A stolen owner SESSION alone
  // (a reusable bearer) must not be able to restore the kill switch and
  // reopen permissive lanes — GO 2/2 demands a FRESH, single-use user
  // verification, redeemed atomically with the restore. Process-local for the
  // same reason as the ceremonies: losing it only makes restore harder.
  const restoreChallenges = new Map<
    string,
    { challenge: string; killEpoch: number; expiresAt: number }
  >();
  const RESTORE_CHALLENGE_TTL_MS = 2 * 60_000;

  function ownerSessionFrom(req: IncomingMessage): OwnerSession | null {
    const token = bearerToken(req);
    return token === null ? null : verifyOwnerSession(token, { now });
  }

  function hasValidDeviceSignature(req: IncomingMessage, rawBody: string): boolean {
    return validDeviceIdFrom(req, rawBody) !== null;
  }

  /**
   * The deviceId behind a VALID device signature, or null. The escalation
   * surface needs the identity, not just the boolean: a delivery ack is
   * recorded against the device that made it, and a relayed channel veto is
   * attributed to the relaying credential.
   */
  function validDeviceIdFrom(req: IncomingMessage, rawBody: string): string | null {
    return validSignatureAgainst(req, rawBody, opts.deviceSecret);
  }

  /**
   * The deviceId behind a valid signature made with the OWNER APP's own
   * secret — the only credential that may drive a PERMISSIVE outcome
   * (`markDelivered()`). Verified against `ownerAppSecret`, never the
   * fleet `deviceSecret`, so a fleet-secret holder (a same-uid agent, the
   * gateway, the escalation service) cannot forge the owner's "I saw it".
   */
  function validOwnerAppDeviceIdFrom(req: IncomingMessage, rawBody: string): string | null {
    return validSignatureAgainst(req, rawBody, opts.ownerAppSecret);
  }

  function validSignatureAgainst(
    req: IncomingMessage,
    rawBody: string,
    secret: string | undefined,
  ): string | null {
    if (secret === undefined) return null;
    const credential = deviceCredentialFrom(req);
    if (credential === null) return null;
    return verifyDeviceSignature(credential, rawBody, secret, { now, seenNonces })
      ? credential.deviceId
      : null;
  }

  // Degraded durability is worth a field only when true: the in-memory state
  // in this response is in force either way, but a restart may not preserve
  // it. Absence of the fields means persistence is healthy (or deliberately
  // ephemeral). `unhealthy` is the harder condition: a failed persist whose
  // stale on-disk state could ALSO not be quarantined — a restart may boot
  // from that stale state, so the plane is not fit for service until an
  // owner repairs the store.
  const degradedFields = () => ({
    ...(killSwitch.persistenceDegraded ? { persistenceDegraded: true as const } : {}),
    ...(killSwitch.quarantineFailed
      ? {
          unhealthy:
            "stale kill state could not be quarantined — durable state is untrustworthy; owner intervention required",
        }
      : {}),
  });

  /**
   * `epoch` is included unconditionally, killed or not: a client needs the
   * CURRENT epoch to tell a stale approval from a fresh one, and that
   * question matters most exactly when killed is false (kill-then-restore
   * flips killed back to false; epoch is what keeps a pre-kill approval
   * dead). Disclosure note (also in packages/mcp/THREAT-MODEL.md): this
   * route is deliberately unauthenticated, so exposing epoch lets ANY
   * caller learn a monotone count of how many times this deployment has
   * ever been killed — not when, not why, not by whom (those still require
   * an owner session). That is a real, if small, widening of what an open
   * endpoint discloses. It is worth it because `killed` alone cannot do
   * this job: a client holding an approval (e.g. an executor's
   * ActionTicket, packages/executor/DESIGN.md §3) must be able to detect
   * that its approval predates a kill even after the system has since been
   * restored, and only a value that never resets can do that.
   */
  // How long a signed kill-state envelope is valid — short, since the broker
  // and control plane share a host (loopback) and thus a clock. The nonce
  // already defeats replay; this bounds it further.
  const KILL_STATE_TTL_MS = 5_000;

  /**
   * The AUTHENTICATED kill-state channel for the broker (blocker: an
   * unauthenticated loopback `/status` can be impersonated by a hostile
   * local process that binds the port after the real control plane stops,
   * answering `{killed:false}` and defeating fail-closed). The caller sends
   * a fresh `nonce`; the response echoes it and is HMAC-signed over
   * {killed, epoch, nonce, expiresAt} with the shared kill-state key. An
   * impostor without the key cannot forge the signature, and a replayed
   * real response carries a stale nonce the caller will reject. `epoch` is
   * always included (killed or not), same as `/status`.
   */
  function getSignedKillState(reqUrl: URL, res: ServerResponse): void {
    if (opts.killStateKey === undefined || opts.killStateKey === "") {
      sendJson(res, 501, { error: "signed kill-state channel is not configured" });
      return;
    }
    const nonce = reqUrl.searchParams.get("nonce");
    if (nonce === null || nonce === "" || nonce.length > 128) {
      sendJson(res, 400, { error: "kill-state requires a nonce (1–128 chars)" });
      return;
    }
    // Optional grant-liveness probe: the broker asks about a specific jti
    // and this plane SIGNS whether it still vouches for that grant — it
    // minted it, remembers it, and its window has not been vetoed. False
    // for anything unknown (including after a restart): a grant this plane
    // cannot vouch for must not dispatch. This is what lets an owner's
    // VETO revoke an already-issued, undispatched grant.
    const jti = reqUrl.searchParams.get("jti");
    if (jti !== null && jti.length > 256) {
      sendJson(res, 400, { error: "kill-state jti probe too long" });
      return;
    }
    let probeFields: { jti: string; grantLive: boolean } | undefined;
    if (jti !== null && jti !== "") {
      const windowId = mintedGrants.get(jti);
      const window = windowId === undefined ? undefined : vetoWindows.get(windowId);
      probeFields = {
        jti,
        grantLive: window !== undefined && window.state !== "vetoed",
      };
    }
    const payload = {
      killed: killSwitch.killed,
      epoch: killSwitch.epoch,
      nonce,
      expiresAt: now() + KILL_STATE_TTL_MS,
      ...(probeFields !== undefined ? probeFields : {}),
    };
    const sig = createHmac("sha256", opts.killStateKey).update(canonicalJson(payload)).digest("hex");
    sendJson(res, 200, { ...payload, sig, ...degradedFields() });
  }

  /**
   * The ATOMIC commit-for-dispatch. The broker calls this as its FINAL
   * check before the merge PUT, and the answer is authoritative rather than
   * a snapshot: this control plane transitions the grant
   * live→committed-for-dispatch here, and a concurrent veto competes for
   * the same jti. Because both this handler and the veto handler are
   * synchronous (no await between reading the state and writing it), the
   * race has exactly one winner — if commit runs first the veto that
   * follows is "in flight" (409), if veto runs first this returns
   * committed:false and the broker sends nothing.
   *
   * The REQUEST is HMAC-signed with the shared kill-state key so ONLY the
   * broker can commit — otherwise a same-uid agent could pre-commit a grant
   * to lock it in ahead of the owner's veto. The response is signed and
   * nonce-bound exactly like the read probe.
   */
  async function postGrantCommit(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (opts.killStateKey === undefined || opts.killStateKey === "") {
      sendJson(res, 501, { error: "signed kill-state channel is not configured" });
      return;
    }
    const parsed = parseJsonBody(await readRawBody(req));
    const jti = parsed.jti;
    const nonce = parsed.nonce;
    const ts = parsed.ts;
    const reqSig = parsed.sig;
    if (
      typeof jti !== "string" ||
      jti === "" ||
      jti.length > 256 ||
      typeof nonce !== "string" ||
      nonce === "" ||
      nonce.length > 128 ||
      typeof ts !== "number" ||
      !Number.isFinite(ts) ||
      typeof reqSig !== "string" ||
      reqSig === ""
    ) {
      sendJson(res, 400, { error: "commit requires {jti, nonce, ts, sig}" });
      return;
    }
    // authenticate the REQUEST: only the broker holds the key
    const expectedReqSig = createHmac("sha256", opts.killStateKey)
      .update(canonicalJson({ jti, nonce, ts }))
      .digest();
    const providedReqSig = Buffer.from(reqSig, "hex");
    if (
      providedReqSig.length !== expectedReqSig.length ||
      !timingSafeEqual(providedReqSig, expectedReqSig)
    ) {
      sendUnauthorized(res);
      return;
    }
    if (Math.abs(now() - ts) > COMMIT_REQUEST_SKEW_MS) {
      sendJson(res, 401, { error: "commit request timestamp is stale" });
      return;
    }

    // THE ATOMIC TRANSITION — no await from here to the state write.
    const windowId = mintedGrants.get(jti);
    const window = windowId === undefined ? undefined : vetoWindows.get(windowId);
    let committed: boolean;
    if (
      window === undefined ||
      window.state === "vetoed" ||
      killSwitch.killed ||
      window.approvalEpoch !== killSwitch.epoch
    ) {
      // a veto/kill/epoch-move won, or the grant is unknown — do NOT commit
      committed = false;
    } else {
      committedGrants.add(jti); // idempotent: a retried commit stays committed
      committed = true;
    }

    const payload = {
      killed: killSwitch.killed,
      epoch: killSwitch.epoch,
      nonce,
      expiresAt: now() + KILL_STATE_TTL_MS,
      jti,
      committed,
    };
    const sig = createHmac("sha256", opts.killStateKey).update(canonicalJson(payload)).digest("hex");
    sendJson(res, 200, { ...payload, sig });
  }

  function getStatus(res: ServerResponse): void {
    if (!killSwitch.killed) {
      sendJson(res, 200, { killed: false, epoch: killSwitch.epoch, ...degradedFields() });
      return;
    }
    // lastKill is tracked directly — this route is polled by every gateway
    // and must not scan an ever-growing audit log.
    const lastKill = killSwitch.lastKill;
    sendJson(res, 200, {
      killed: true,
      reason: lastKill?.reason,
      at: lastKill?.at,
      epoch: killSwitch.epoch,
      ...degradedFields(),
    });
  }

  async function postKill(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // The raw body is read before parsing because the device HMAC covers the
    // exact bytes on the wire.
    const raw = await readRawBody(req);
    const authenticated = hasValidDeviceSignature(req, raw) || ownerSessionFrom(req) !== null;

    if (!authenticated && !isLoopbackAddress(req.socket.remoteAddress)) {
      sendUnauthorized(res);
      return;
    }

    const body = parseJsonBody(raw);
    const claimed = KILL_SOURCES.includes(body.source as KillSource)
      ? (body.source as KillSource)
      : "api";
    // An unverified source claim is not trusted: unauthenticated loopback
    // kills are recorded as plain "api" kills, flagged in the audit trail.
    const source = authenticated ? claimed : "api";
    const reason = typeof body.reason === "string" ? body.reason : undefined;
    killSwitch.engage(source, reason, { unauthenticated: !authenticated });
    // A kill voids every outstanding approval ceremony: a challenge minted
    // before the kill must never be redeemable after a restore (its epoch
    // no longer matches, but clearing is the belt to that suspenders).
    approvalChallenges.clear();
    // ...and every outstanding login challenge, so a kill also stops a
    // half-finished session bootstrap. (Login challenges minted AFTER this
    // kill, for the restore that follows, are stamped with the new epoch and
    // survive; only pre-kill ones are cleared.)
    loginChallenges.clear();
    // ...and every outstanding GO 2/2 restore challenge. A NEW kill landing
    // while a restore ceremony for a PRIOR kill is in flight bumps the epoch,
    // which already invalidates both the ceremony and its challenge; clearing
    // is the belt to that suspenders and keeps the map from holding corpses.
    restoreChallenges.clear();
    // The kill is in force in memory no matter what; the response only claims
    // durability when the persist actually succeeded.
    sendJson(res, 200, { killed: true, ...degradedFields() });
  }

  async function postAlert(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Same auth shape as /kill — an alert is attributed the same way — but it
    // only records a flagged event; it never engages the switch, so it can
    // never be a one-touch denial of service.
    const raw = await readRawBody(req);
    const authenticated = hasValidDeviceSignature(req, raw) || ownerSessionFrom(req) !== null;

    if (!authenticated && !isLoopbackAddress(req.socket.remoteAddress)) {
      sendUnauthorized(res);
      return;
    }

    const body = parseJsonBody(raw);
    const claimed = KILL_SOURCES.includes(body.source as KillSource)
      ? (body.source as KillSource)
      : "api";
    const source = authenticated ? claimed : "api";
    const reason = typeof body.reason === "string" ? body.reason : undefined;
    killSwitch.alert(source, reason, { unauthenticated: !authenticated });
    sendJson(res, 200, { alerted: true, killed: killSwitch.killed });
  }

  async function postCeremonyStart(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // GO 1/2. Owner session required — no exceptions, no loopback bypass.
    const session = ownerSessionFrom(req);
    if (session === null) {
      sendUnauthorized(res);
      return;
    }
    parseJsonBody(await readRawBody(req)); // drain and validate; nothing else is trusted from the body
    if (!killSwitch.killed) {
      sendJson(res, 409, { error: "not killed — nothing to restore" });
      return;
    }
    // Dead records first, BEFORE any capacity decision: a ceremony that is
    // past its TTL, already consumed, or bound to a superseded kill epoch is
    // unspendable by every path in this file, so it must never hold a slot
    // against the one ceremony that matters. (An earlier version purged only
    // TTL expiry, which let corpses block new ceremonies for minutes — a
    // lockout of restore, the exact operation this system exists to protect.)
    for (const [staleId, record] of ceremonies) {
      const dead =
        now() >= record.ceremony.expiresAt ||
        record.ceremony.state === "completed" ||
        record.epoch !== killSwitch.epoch;
      if (dead) ceremonies.delete(staleId);
    }
    // One live ceremony per owner per kill epoch, and GO 1/2 is IDEMPOTENT:
    // while this owner already has a live ceremony (post-purge, so it is
    // current-epoch, unconsumed and unexpired), return THAT ceremony with
    // its clocks untouched. A double-click, a browser retry or a second tab
    // must not invalidate the id the owner is holding — and a stolen
    // same-owner session must not be able to reset the cooldown forever by
    // hammering this route. There is deliberately no way to abandon a
    // pending ceremony early: it ends by TTL expiry, consumption, or a new
    // kill epoch — any owner-session cancel verb would reopen the same
    // stolen-session lockout this idempotency closes.
    for (const [existingId, record] of ceremonies) {
      if (record.ceremony.ownerId === session.ownerId) {
        sendJson(res, 200, {
          id: existingId,
          state: record.ceremony.tick(),
          cooldownRemainingMs: record.ceremony.cooldownRemainingMs(),
          expiresAt: record.ceremony.expiresAt,
        });
        return;
      }
    }
    // THE ONE LICENSE GATE in the system (license.ts doctrine): minting a
    // NEW 2GO ceremony is the paid act. It sits after the idempotent
    // return — a ceremony the owner already holds is never yanked away by
    // a mid-flight lapse — and nothing on any stop path ever reaches this
    // check. 402, the HTTP status that says exactly what this is.
    if (opts.licensing !== undefined) {
      const verdict = verifyLicense(
        opts.licensing.token ?? "",
        opts.licensing.vendorPublicKeyPem,
        now(),
        opts.licensing.deploymentId,
      );
      if (!verdict.ok) {
        sendJson(res, 402, {
          error:
            `2GO restore requires an active OwnerSwitch license: ${verdict.reason}. ` +
            "Stopping, vetoes, acks and the audit trail are free forever and unaffected.",
        });
        return;
      }
      if (verdict.state === "grace") {
        console.error(
          `[ownerswitch] restore ceremony started on the 72 h grace of an EXPIRED license ` +
            `("${verdict.license.licensee}") — renew now.`,
        );
      }
    }
    // Secondary backstop only — with the purge and the one-per-owner rule
    // above, size counts distinct owners, so reaching this ceiling means a
    // flood of hostile sessions, not normal use. Full fails closed: new
    // ceremonies are refused (an owner with a pending one still gets it back
    // via the idempotent path above), a live ceremony is never evicted to
    // make room, and fullness can only ever deny a restore path, never open
    // one.
    if (ceremonies.size >= MAX_CEREMONY_RECORDS) {
      sendJson(res, 409, { error: "ceremony rejected" });
      return;
    }
    // Unguessable capability id: 122 bits from the CSPRNG. Holding one id
    // (or watching them mint) must not help anyone name another.
    const id = `cer_${randomUUID()}`;
    const ceremony = new RestoreCeremony(id, session.ownerId, { now });
    ceremonies.set(id, { ceremony, epoch: killSwitch.epoch });
    sendJson(res, 201, {
      id,
      state: ceremony.tick(),
      cooldownRemainingMs: ceremony.cooldownRemainingMs(),
      expiresAt: ceremony.expiresAt,
    });
  }

  function getCeremony(req: IncomingMessage, res: ServerResponse, id: string): void {
    const session = ownerSessionFrom(req);
    if (session === null) {
      sendUnauthorized(res);
      return;
    }
    const record = ceremonies.get(id);
    // Another owner's ceremony reads as absent — existence is not revealed.
    if (record === undefined || record.ceremony.ownerId !== session.ownerId) {
      sendJson(res, 404, { error: `no ceremony "${id}"` });
      return;
    }
    const ticked = record.ceremony.tick();
    // "completed" only ever happens via /restore, so it reads as consumed; a
    // ceremony from a superseded kill epoch is dead and reads as expired.
    const state =
      ticked === "completed"
        ? "consumed"
        : record.epoch !== killSwitch.epoch
          ? "expired"
          : ticked;
    sendJson(res, 200, {
      state,
      cooldownRemainingMs: record.ceremony.cooldownRemainingMs(),
      expiresAt: record.ceremony.expiresAt,
    });
  }

  /**
   * Mint the GO 2/2 restore assertion challenge for a live ceremony: a
   * single-use, short-lived challenge the owner's passkey must sign to
   * complete the restore, bound server-side to {ceremonyId, killEpoch}. This
   * is what makes a stolen owner SESSION insufficient to restore — GO 2/2
   * additionally demands a fresh user verification from the enrolled
   * authenticator. Only meaningful with a passkey enrolled; in a dev instance
   * without one, GO 2/2 stays session-only (and this endpoint reports 501).
   */
  async function postRestoreChallenge(
    req: IncomingMessage,
    res: ServerResponse,
    id: string,
  ): Promise<void> {
    const session = ownerSessionFrom(req);
    if (session === null) {
      sendUnauthorized(res);
      return;
    }
    if (opts.ownerPasskey === undefined) {
      sendJson(res, 501, {
        error: "no owner approval passkey is enrolled — GO 2/2 is session-only on this control plane",
      });
      return;
    }
    // A failed quarantine keeps restore denied entirely (see postRestore);
    // do not hand out a challenge for a restore that must not complete.
    if (killSwitch.quarantineFailed) {
      sendJson(res, 409, { error: "restore is unavailable — durable kill state is untrustworthy" });
      return;
    }
    const record = ceremonies.get(id);
    // Another owner's ceremony reads as absent — existence is not revealed.
    if (record === undefined || record.ceremony.ownerId !== session.ownerId) {
      sendJson(res, 404, { error: `no ceremony "${id}"` });
      return;
    }
    if (!killSwitch.killed) {
      sendJson(res, 409, { error: "not killed — nothing to restore" });
      return;
    }
    if (record.epoch !== killSwitch.epoch) {
      sendJson(res, 409, { error: "the ceremony is bound to a superseded kill epoch — start a fresh one" });
      return;
    }
    await readRawBody(req); // drain
    // RE-CHECK after the await: a kill can land while the body drains, bumping
    // the epoch. A challenge minted into a moved epoch would be dead anyway
    // (redemption checks equality), but never mint it in the first place.
    if (!killSwitch.killed || record.epoch !== killSwitch.epoch) {
      sendJson(res, 409, { error: "the kill epoch moved while starting GO 2/2 — start a fresh ceremony" });
      return;
    }
    // GO 2/2 unlocks only past the cooldown. Minting the challenge only when
    // the ceremony is READY keeps it inside its short TTL and refuses to hand
    // out a challenge that confirm() would reject as premature anyway.
    const ticked = record.ceremony.tick();
    if (ticked !== "ready") {
      sendJson(res, 409, {
        error: `GO 2/2 is not yet available (ceremony state "${ticked}") — wait out the cooldown`,
      });
      return;
    }
    const challenge = randomBytes(32).toString("base64url");
    restoreChallenges.set(id, {
      challenge,
      killEpoch: killSwitch.epoch,
      expiresAt: now() + RESTORE_CHALLENGE_TTL_MS,
    });
    sendJson(res, 200, {
      challenge,
      rpId: opts.ownerPasskey.rpId,
      credentialId: opts.ownerPasskey.credentialId,
      // domain-separation: what this assertion authorizes, echoed for the app
      purpose: "restore-go2",
      ceremonyId: id,
      killEpoch: killSwitch.epoch,
      expiresAt: now() + RESTORE_CHALLENGE_TTL_MS,
    });
  }

  async function postRestore(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // GO 2/2. Owner session required — no exceptions, no loopback bypass.
    // Restoring is the expensive direction and stays that way.
    const session = ownerSessionFrom(req);
    if (session === null) {
      sendUnauthorized(res);
      return;
    }
    const body = parseJsonBody(await readRawBody(req));
    const ceremonyId = typeof body.ceremonyId === "string" ? body.ceremonyId : "";
    const record = ceremonies.get(ceremonyId);
    // Every rejection is the same generic 409 — a uniform response SHAPE, so
    // the body never says which check failed (wrong owner, wrong epoch,
    // timing, replay). It is NOT a constant-time or side-channel-free
    // guarantee: evaluation order, timing and transport metadata still
    // differ between causes.
    const rejected = () => sendJson(res, 409, { error: "restore rejected" });
    // A failed quarantine means stale kill state may survive on disk and a
    // restart may boot from it. Until an owner repairs the store, the plane
    // must not become ready: restores stay denied, because flipping the
    // in-memory switch is the only working stop left.
    if (killSwitch.quarantineFailed) return rejected();
    if (record === undefined) return rejected();
    if (record.ceremony.ownerId !== session.ownerId) return rejected();
    if (record.epoch !== killSwitch.epoch) return rejected();
    if (!killSwitch.killed) return rejected();

    // The owner SESSION is a REUSABLE bearer token; a stolen one must not be
    // able to restore the kill switch and reopen permissive lanes. With a
    // passkey enrolled, GO 2/2 additionally requires a FRESH single-use
    // WebAuthn assertion over a challenge bound to THIS ceremony and THIS kill
    // epoch — consumed atomically here, in the same synchronous tail as the
    // ceremony's own single-use confirm(). A dev instance without a passkey
    // stays session-only (and says so via the challenge endpoint's 501).
    if (opts.ownerPasskey !== undefined) {
      const chal = restoreChallenges.get(ceremonyId);
      // atomic single-use: SPENT by this attempt, verified or not — a failed
      // attempt needs a fresh challenge, exactly like an approval ceremony.
      restoreChallenges.delete(ceremonyId);
      if (chal === undefined || now() >= chal.expiresAt) {
        sendJson(res, 401, {
          error:
            "no live GO 2/2 assertion challenge — request POST /restore/ceremony/:id/challenge " +
            "and sign it with the enrolled passkey (challenges are single-use and short-lived)",
        });
        return;
      }
      // EPOCH binding: a challenge minted in one kill epoch must not authorize
      // a restore in another. A kill between mint and redemption bumps the
      // epoch (and clears the map); this is the belt to that suspenders.
      if (chal.killEpoch !== killSwitch.epoch) {
        sendJson(res, 401, {
          error: "the GO 2/2 challenge was minted in a different kill epoch — request a fresh one",
        });
        return;
      }
      const assertion = assertionFrom(body.assertion);
      if (assertion === null) {
        sendJson(res, 400, {
          error:
            "restore requires assertion: {credentialId, clientDataJSON, authenticatorData, " +
            "signature}, each base64url",
        });
        return;
      }
      const verdict = verifyOwnerAssertion(assertion, {
        passkey: opts.ownerPasskey,
        rpId: opts.ownerPasskey.rpId,
        expectedOrigin: opts.ownerPasskey.origin,
        expectedChallenge: chal.challenge,
        lastSignCount: passkeySignCount,
      });
      if (!verdict.ok) {
        sendJson(res, 401, { error: `passkey assertion rejected: ${verdict.reason}` });
        return;
      }
      passkeySignCount = Math.max(passkeySignCount, verdict.signCount);
    }
    // No passkey enrolled: the 2GO ceremony (owner session + mandatory
    // cooldown + single-use) is the restore boundary, exactly as before — a
    // deployment with no authenticator has no second factor to assert with.
    // A LIVE MERGE deployment always enrolls a passkey (the production
    // launcher requires one), so its restore is always assertion-gated by the
    // branch above; the session-only path here is the dev/quickstart and the
    // pure kill-switch (no grant key), where it was already accepted.

    try {
      // confirm() is the atomic consume: it only succeeds in "ready" (past
      // the cooldown, inside the TTL) and transitions to "completed" before
      // returning, so a concurrent second spend throws. Single-spend holds
      // for one process and one event loop — where all ceremony state lives.
      killSwitch.restore(record.ceremony.confirm());
    } catch {
      return rejected();
    }
    sendJson(res, 200, { killed: false });
  }

  async function postVeto(req: IncomingMessage, res: ServerResponse, id: string): Promise<void> {
    // An APPROVAL names an owner, so it stays authenticated by an owner
    // SESSION — a token on the owner's device, NOT the gateway's device
    // secret. That is exactly why an approval is a boundary a same-uid agent
    // cannot cross: it can forge a registration (device secret), but not the
    // owner's session. A VETO additionally accepts a device signature — the
    // escalation ladder relays SMS replies and DTMF keypresses under its
    // device credential (escalation DESIGN.md §3), and the owner app's
    // one-tap stop rides its enrolled-device key. Stops are cheap and
    // attributable; the device path carries no other verb (deny-only, the
    // same doctrine as the kill surface).
    const raw = await readRawBody(req);
    const session = ownerSessionFrom(req);
    if (session === null) {
      return postDeviceVeto(req, res, id, raw);
    }
    const window = vetoWindows.get(id);
    if (!window) {
      sendJson(res, 404, { error: `no veto window "${id}"` });
      return;
    }
    const body = parseJsonBody(raw);
    const decision = body.decision ?? "veto";
    if (decision !== "veto" && decision !== "approve") {
      sendJson(res, 400, { error: 'decision must be "veto" or "approve"' });
      return;
    }
    if (decision === "approve") {
      // Active approval is the merge lane's authorizing event. It is only
      // meaningful for a grant-eligible window (a github/merge_pull_request
      // call whose args pass the closed schema) — nothing else mints a
      // grant, so approving anything else is a category error, refused.
      const canonicalArgs = grantEligibleArgs(window);
      if (canonicalArgs === null) {
        sendJson(res, 400, {
          error:
            "this window is not grant-eligible (only a github/merge_pull_request call with " +
            "valid closed arguments can be actively approved); it releases on the veto lane's " +
            "own terms, not by approval",
        });
        return;
      }
      // Fail closed: no approval may be minted while killed, and the approval
      // binds the CURRENT (live, post-restore) epoch — so a window that was
      // registered during a kill cannot be turned into authority that
      // outlives the kill. A kill after this approval moves the epoch and the
      // grant is spent.
      if (killSwitch.killed) {
        sendJson(res, 409, {
          error: "cannot approve while the kill switch is engaged — restore first, then re-approve",
        });
        return;
      }
      // The session identifies the owner but is a REUSABLE bearer token — a
      // stolen one must not mint merge authority. With a passkey enrolled,
      // approval additionally requires a fresh WebAuthn assertion over a
      // single-use challenge bound to THIS window and THIS exact call.
      if (opts.ownerPasskey !== undefined) {
        const ceremony = approvalChallenges.get(id);
        // atomic single-use: the ceremony is SPENT by this redemption
        // attempt, verified or not — a failed attempt needs a fresh one
        approvalChallenges.delete(id);
        if (ceremony === undefined || now() >= ceremony.expiresAt) {
          sendJson(res, 401, {
            error:
              "no live approval ceremony for this window — request POST /veto/:id/approval-challenge " +
              "and sign it with the enrolled passkey (challenges are single-use and short-lived)",
          });
          return;
        }
        // EPOCH binding: a ceremony minted in one kill epoch must not
        // authorize a merge in another. A challenge created before a kill
        // could otherwise survive a restore (within its TTL) and, redeemed
        // after, bind window.approve() to the post-restore epoch — laundering
        // a pre-kill "yes" into a post-kill world. (Kills also clear the map;
        // this is the belt to that suspenders, and covers the epoch moving
        // without a kill-in-force at redemption time.)
        if (ceremony.killEpoch !== killSwitch.epoch) {
          sendJson(res, 401, {
            error: "the approval ceremony was minted in a different kill epoch — request a fresh one",
          });
          return;
        }
        // the ceremony binds the exact call; if the window's args changed
        // out from under it (impossible via this API, checked anyway), the
        // signature must not be transferable to the new bytes
        if (ceremony.callHash !== sha256Hex(canonicalArgs)) {
          sendJson(res, 401, { error: "the approval ceremony was minted for different call bytes" });
          return;
        }
        const assertion = assertionFrom(body.assertion);
        if (assertion === null) {
          sendJson(res, 400, {
            error:
              "approve requires assertion: {credentialId, clientDataJSON, authenticatorData, " +
              "signature}, each base64url",
          });
          return;
        }
        const verdict = verifyOwnerAssertion(assertion, {
          passkey: opts.ownerPasskey,
          rpId: opts.ownerPasskey.rpId,
          expectedOrigin: opts.ownerPasskey.origin,
          expectedChallenge: ceremony.challenge,
          lastSignCount: passkeySignCount,
        });
        if (!verdict.ok) {
          sendJson(res, 401, { error: `passkey assertion rejected: ${verdict.reason}` });
          return;
        }
        passkeySignCount = Math.max(passkeySignCount, verdict.signCount);
      } else if (opts.dev !== true) {
        // no passkey enrolled and not a dev instance: a bearer session alone
        // must not mint merge authority — refuse until enrollment
        sendJson(res, 403, {
          error:
            "no owner approval passkey is enrolled — a production control plane refuses " +
            "session-only merge approval; enroll a passkey (ownerPasskey) or run dev mode",
        });
        return;
      }
      try {
        window.approve(session.ownerId, killSwitch.epoch);
        sendJson(res, 200, { status: "approved" });
      } catch (err) {
        sendJson(res, 409, { error: err instanceof Error ? err.message : String(err) });
      }
      return;
    }
    // Too late to veto once the grant is COMMITTED for dispatch: the merge
    // is in flight and cannot be recalled. Reported honestly rather than
    // accepting a veto that does nothing. This branch and the commit handler
    // are synchronous, so exactly one of them wins the race.
    const grantJti = windowToGrant.get(id);
    if (grantJti !== undefined && committedGrants.has(grantJti)) {
      sendJson(res, 409, {
        error: "the approved merge is already committed for dispatch (in flight) — too late to veto",
      });
      return;
    }
    try {
      window.veto(session.ownerId);
      sendJson(res, 200, { status: window.state });
    } catch (err) {
      sendJson(res, 409, { error: err instanceof Error ? err.message : String(err) });
    }
  }

  /**
   * The device-signed veto relay — the deny-only half of POST /veto/:id.
   * Carries exactly one verb: stop. `decision: "approve"` under a device
   * signature is refused loudly — a device credential must never mint the
   * merge lane's authorizing event, however the request is shaped.
   *
   * Attribution is honest about its weakness: a relayed channel stop names
   * the channel ("channel:sms-reply", "channel:voice-dtmf"), never a person
   * — a forged SMS after a SIM swap stopped something, and the audit trail
   * should say a phone did it, not the owner. Without an attribution the
   * stop is recorded against the signing device id.
   *
   * IDEMPOTENT: re-vetoing a vetoed window succeeds as a no-op, so the
   * owner app's service worker and the ladder can blind-retry a send they
   * cannot prove arrived.
   */
  async function postDeviceVeto(
    req: IncomingMessage,
    res: ServerResponse,
    id: string,
    raw: string,
  ): Promise<void> {
    const deviceId = validDeviceIdFrom(req, raw);
    if (deviceId === null) {
      sendUnauthorized(res);
      return;
    }
    const window = vetoWindows.get(id);
    if (!window) {
      sendJson(res, 404, { error: `no veto window "${id}"` });
      return;
    }
    const body = parseJsonBody(raw);
    if (body.decision !== undefined && body.decision !== "veto") {
      sendJson(res, 403, {
        error: "a device credential carries exactly one verb here: veto — approval requires the owner's session and passkey",
      });
      return;
    }
    let attribution = `device:${deviceId}`;
    if (body.attribution !== undefined) {
      if (
        typeof body.attribution !== "string" ||
        !/^channel:[a-z0-9][a-z0-9-]{0,62}$/.test(body.attribution)
      ) {
        sendJson(res, 400, {
          error: 'attribution must be "channel:<kind>" (lowercase alphanumeric/hyphen), e.g. "channel:sms-reply"',
        });
        return;
      }
      attribution = body.attribution;
    }
    if (window.state === "vetoed") {
      sendJson(res, 200, { status: "vetoed" });
      return;
    }
    // Too late once the grant is committed for dispatch — same honest 409 as
    // the session path; the two handlers stay synchronous so the race with
    // the commit handler has exactly one winner.
    const grantJti = windowToGrant.get(id);
    if (grantJti !== undefined && committedGrants.has(grantJti)) {
      sendJson(res, 409, {
        error: "the approved merge is already committed for dispatch (in flight) — too late to veto",
      });
      return;
    }
    try {
      window.veto(attribution);
      sendJson(res, 200, { status: window.state });
    } catch (err) {
      sendJson(res, 409, { error: err instanceof Error ? err.message : String(err) });
    }
  }

  /**
   * POST /veto/:id/seen — the production caller of markDelivered(), and the
   * ONLY caller (escalation DESIGN.md §3): the enrolled device reports the
   * alert was rendered in front of a human. Authenticated with the OWNER
   * APP's own secret (`ownerAppSecret`), NEVER the fleet `deviceSecret` —
   * this is the PERMISSIVE bit of the veto lane (it lets silence release a
   * held call), so it must ride a credential no fleet component and no
   * same-uid agent holds. Nothing a carrier, a webhook, an owner session, or
   * a fleet-signed request may flip it.
   *
   * When no owner-app secret is enrolled the endpoint is 501 and delivery
   * confirmation stays UNWIRED — every window then walks to held → passkey
   * approval, the fail-closed default, rather than trusting a weaker
   * credential to speak for the owner.
   *
   * A last-second ack must never convert straight into a release the owner
   * had no time to answer: inside the response floor (60 s before the
   * deadline) the ack is refused, the window extends or holds on its own
   * clock, and the device is told to re-ack against the new deadline.
   */
  async function postVetoSeen(req: IncomingMessage, res: ServerResponse, id: string): Promise<void> {
    const raw = await readRawBody(req);
    if (opts.ownerAppSecret === undefined) {
      sendJson(res, 501, {
        error:
          "delivery confirmation is not wired: no owner-app credential is enrolled on this control " +
          "plane, so no device may flip the release-permitting 'delivered' bit — windows walk to " +
          "held (passkey approval) instead. Provision ownerAppSecret (OWNERSWITCH_OWNER_APP_SECRET).",
      });
      return;
    }
    const deviceId = validOwnerAppDeviceIdFrom(req, raw);
    if (deviceId === null) {
      sendUnauthorized(res);
      return;
    }
    const window = vetoWindows.get(id);
    if (!window) {
      sendJson(res, 404, { error: `no veto window "${id}"` });
      return;
    }
    // idempotent: a delivered window stays delivered; re-acks succeed
    if (window.isDelivered) {
      sendJson(res, 200, { status: window.tick(), delivered: true, deadline: window.deadlineAt });
      return;
    }
    const status = window.tick();
    if (status !== "pending" && status !== "extended") {
      sendJson(res, 409, { error: `cannot ack in status "${status}"` });
      return;
    }
    if (now() > window.deadlineAt - MIN_VETO_RESPONSE_MS) {
      sendJson(res, 409, {
        error:
          "ack arrived inside the minimum veto-response floor (60 s before the deadline) — not counted; " +
          "the window will extend or hold, re-ack against the new deadline",
      });
      return;
    }
    window.markDelivered(deviceId);
    sendJson(res, 200, { status, delivered: true, deadline: window.deadlineAt });
  }

  /**
   * GET /veto/pending — the listing the escalation ladder polls to discover
   * work. Device-signed: window contents describe held agent actions, so the
   * listing is authenticated like registration is. Serves only windows still
   * open (pending/extended, after a tick), each with the deadline and
   * delivered bit the ladder paces itself off.
   */
  async function getVetoPending(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const raw = await readRawBody(req);
    if (validDeviceIdFrom(req, raw) === null) {
      sendUnauthorized(res);
      return;
    }
    const windows: Array<{
      id: string;
      status: VetoWireStatus;
      agentId: string;
      tool: string;
      deadline: number;
      delivered: boolean;
    }> = [];
    for (const [windowId, window] of vetoWindows) {
      const status = window.tick();
      if (status !== "pending" && status !== "extended") continue;
      windows.push({
        id: windowId,
        status,
        agentId: window.call.agentId,
        tool: window.call.tool,
        deadline: window.deadlineAt,
        delivered: window.isDelivered,
      });
    }
    sendJson(res, 200, { windows });
  }

  /** The wire assertion, or null when the body doesn't carry a usable one. */
  function assertionFrom(value: unknown): WebAuthnAssertion | null {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
    const { credentialId, clientDataJSON, authenticatorData, signature } = value as Record<
      string,
      unknown
    >;
    if (
      typeof credentialId !== "string" ||
      credentialId === "" ||
      typeof clientDataJSON !== "string" ||
      clientDataJSON === "" ||
      clientDataJSON.length > 8 * 1024 ||
      typeof authenticatorData !== "string" ||
      authenticatorData === "" ||
      authenticatorData.length > 8 * 1024 ||
      typeof signature !== "string" ||
      signature === "" ||
      signature.length > 4 * 1024
    ) {
      return null;
    }
    return { credentialId, clientDataJSON, authenticatorData, signature };
  }

  /**
   * Mint the approval CEREMONY for a grant-eligible window: a single-use,
   * short-lived challenge the owner's passkey must sign, bound server-side
   * to the window and the exact call bytes it would approve. Owner-session
   * authenticated — the ceremony is the second factor, not a replacement
   * for the first.
   */
  async function postApprovalChallenge(
    req: IncomingMessage,
    res: ServerResponse,
    id: string,
  ): Promise<void> {
    const session = ownerSessionFrom(req);
    if (session === null) {
      sendUnauthorized(res);
      return;
    }
    if (opts.ownerPasskey === undefined) {
      sendJson(res, 501, { error: "no owner approval passkey is enrolled on this control plane" });
      return;
    }
    const window = vetoWindows.get(id);
    if (!window) {
      sendJson(res, 404, { error: `no veto window "${id}"` });
      return;
    }
    const canonicalArgs = grantEligibleArgs(window);
    if (canonicalArgs === null) {
      sendJson(res, 400, { error: "approval ceremonies exist only for grant-eligible windows" });
      return;
    }
    if (killSwitch.killed) {
      sendJson(res, 409, { error: "cannot open an approval ceremony while the kill switch is engaged" });
      return;
    }
    await readRawBody(req); // drain
    // RE-CHECK kill AFTER the await: a kill can land while the body drains,
    // and a challenge minted into a killed world must not exist.
    if (killSwitch.killed) {
      sendJson(res, 409, { error: "cannot open an approval ceremony while the kill switch is engaged" });
      return;
    }
    // The TYPED, per-field renderable the owner app displays — never raw
    // canonical JSON — with every string field proven safe to display. Its
    // hash is bound into the ceremony, so the passkey signs a challenge tied
    // to exactly the transaction the owner saw.
    let renderable;
    try {
      renderable = buildRenderableApproval(parseMergePrArgs(canonicalArgs));
    } catch (err) {
      sendJson(res, 400, {
        error: `cannot render this call for owner approval: ${err instanceof Error ? err.message : "unsafe"}`,
      });
      return;
    }
    const renderHash = sha256Hex(canonicalJson(renderable));
    const challenge = randomBytes(32).toString("base64url");
    approvalChallenges.set(id, {
      challenge,
      callHash: sha256Hex(canonicalArgs),
      renderHash,
      killEpoch: killSwitch.epoch,
      expiresAt: now() + APPROVAL_CHALLENGE_TTL_MS,
    });
    sendJson(res, 200, {
      challenge,
      rpId: opts.ownerPasskey.rpId,
      credentialId: opts.ownerPasskey.credentialId,
      // what the ceremony approves — a typed, sanitized, per-field render for
      // the owner app, plus the hashes the challenge is bound to
      renderable,
      renderHash,
      callHash: sha256Hex(canonicalArgs),
      expiresAt: now() + APPROVAL_CHALLENGE_TTL_MS,
    });
  }

  /**
   * Passkey login — step 1: mint a single-use challenge the owner's
   * authenticator will sign to prove it is present. Requires a passkey to be
   * enrolled; the challenge grants nothing on its own.
   */
  async function postSessionChallenge(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (opts.ownerPasskey === undefined) {
      sendJson(res, 501, { error: "no owner approval passkey is enrolled on this control plane" });
      return;
    }
    // Login is DELIBERATELY allowed while killed. After a control-plane
    // restart with persisted KILL, every process-local session is gone, so
    // refusing login here would deadlock recovery — nobody could authenticate
    // to drive the restore ceremony. A login is safe while killed because it
    // proves nothing but the owner's presence: the session it yields cannot
    // approve a merge (refused while killed) and cannot by itself restore
    // (GO 2/2 demands a second, fresh assertion), so a session minted while
    // killed is effectively restore-scoped by the kill state itself.
    await readRawBody(req); // drain
    // sweep expired challenges so the map stays bounded, and cap the map as a
    // backstop against an unauthenticated flood (these are open to mint).
    for (const [ch, rec] of loginChallenges) if (now() >= rec.expiresAt) loginChallenges.delete(ch);
    if (loginChallenges.size >= MAX_LOGIN_CHALLENGES) {
      sendJson(res, 503, { error: "too many pending login challenges — retry shortly" });
      return;
    }
    const challenge = randomBytes(32).toString("base64url");
    // Stamp the CURRENT (post-drain) kill epoch: read as late as possible so a
    // kill that lands while the body drained is reflected here, and required
    // to still match at redemption. A challenge cannot silently cross a kill.
    loginChallenges.set(challenge, { expiresAt: now() + LOGIN_CHALLENGE_TTL_MS, killEpoch: killSwitch.epoch });
    sendJson(res, 200, {
      challenge,
      rpId: opts.ownerPasskey.rpId,
      credentialId: opts.ownerPasskey.credentialId,
      expiresAt: now() + LOGIN_CHALLENGE_TTL_MS,
    });
  }

  /**
   * Passkey login — step 2: redeem a signed assertion for an owner SESSION.
   * The challenge is spent atomically (deleted before verification), the
   * assertion is verified against the enrolled passkey (origin, UP+UV,
   * counter), and only then is a session minted. This is what lets a fresh
   * PRODUCTION process begin the approval flow — the alternative (no way to
   * get a session) leaves the passkey approval endpoints unreachable.
   */
  async function postSession(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (opts.ownerPasskey === undefined) {
      sendJson(res, 501, { error: "no owner approval passkey is enrolled on this control plane" });
      return;
    }
    // Allowed while killed — see postSessionChallenge: the session is the only
    // way to reach the restore ceremony after a restart, and it authorizes
    // nothing destructive on its own.
    const body = parseJsonBody(await readRawBody(req));
    const challenge = body.challenge;
    if (typeof challenge !== "string" || challenge === "") {
      sendJson(res, 400, { error: "session requires the challenge and a passkey assertion" });
      return;
    }
    const record = loginChallenges.get(challenge);
    loginChallenges.delete(challenge); // single-use: spent by this attempt
    if (record === undefined || now() >= record.expiresAt) {
      sendJson(res, 401, { error: "no live login challenge — request POST /session/challenge first" });
      return;
    }
    // Epoch equality: a challenge minted in one kill epoch cannot be redeemed
    // in another. A KILL between mint and redemption bumps the epoch and kills
    // the challenge — it never crosses the kill boundary into a fresh session.
    if (record.killEpoch !== killSwitch.epoch) {
      sendJson(res, 401, {
        error: "the login challenge was minted in a different kill epoch — request a fresh one",
      });
      return;
    }
    const assertion = assertionFrom(body.assertion);
    if (assertion === null) {
      sendJson(res, 400, { error: "session requires a well-formed passkey assertion" });
      return;
    }
    const verdict = verifyOwnerAssertion(assertion, {
      passkey: opts.ownerPasskey,
      rpId: opts.ownerPasskey.rpId,
      expectedOrigin: opts.ownerPasskey.origin,
      expectedChallenge: challenge,
      lastSignCount: passkeySignCount,
    });
    if (!verdict.ok) {
      sendJson(res, 401, { error: `passkey assertion rejected: ${verdict.reason}` });
      return;
    }
    passkeySignCount = Math.max(passkeySignCount, verdict.signCount);
    const session = createOwnerSession("owner", { now });
    sendJson(res, 200, { token: session.token, expiresAt: session.expiresAt });
  }

  /** The registered call, or null when the body doesn't describe one. */
  function toolCallFrom(value: unknown): ToolCall | null {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
    const { agentId, tool, args } = value as Record<string, unknown>;
    if (typeof agentId !== "string" || agentId === "") return null;
    if (typeof tool !== "string" || tool === "") return null;
    if (args !== undefined && (typeof args !== "object" || args === null || Array.isArray(args))) {
      return null;
    }
    return { agentId, tool, args: args as Record<string, unknown> | undefined };
  }

  /**
   * The registered purpose, validated with the same closed-schema stance as
   * everything else on this surface: exactly {connector, operation,
   * policyVersion?}, nothing more. When the purpose is the grant-eligible
   * pair, the call's arguments must ALSO parse under the closed merge
   * schema — a "merge-purpose" window whose arguments are not exactly one
   * merge must never be put in front of the owner, let alone signed later.
   * Throws with the message to serve as a 400.
   */
  function vetoPurposeFrom(value: unknown, call: ToolCall): VetoPurpose | undefined {
    if (value === undefined) return undefined;
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new Error("purpose must be an object with string connector and operation");
    }
    for (const key of Object.keys(value)) {
      if (key !== "connector" && key !== "operation" && key !== "policyVersion") {
        throw new Error(`unknown purpose field "${key}" — allowed: connector, operation, policyVersion`);
      }
    }
    const { connector, operation, policyVersion } = value as Record<string, unknown>;
    if (typeof connector !== "string" || connector === "") {
      throw new Error("purpose.connector must be a non-empty string");
    }
    if (typeof operation !== "string" || operation === "") {
      throw new Error("purpose.operation must be a non-empty string");
    }
    if (policyVersion !== undefined && typeof policyVersion !== "string") {
      throw new Error("purpose.policyVersion must be a string when present");
    }
    if (connector === GITHUB_CONNECTOR && operation === MERGE_PULL_REQUEST) {
      try {
        parseMergePrArgs(canonicalJson(call.args ?? {}));
      } catch (err) {
        throw new Error(
          `a ${GITHUB_CONNECTOR}/${MERGE_PULL_REQUEST} window requires arguments that parse ` +
            `under the closed merge schema: ${err instanceof Error ? err.message : "invalid"}`,
        );
      }
    }
    return { connector, operation, policyVersion: policyVersion ?? "" };
  }

  async function postRegisterVeto(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Strictly device-authenticated: whoever registers decides what the owner
    // gets asked about. Unauthenticated callers must not reach the owner.
    const raw = await readRawBody(req);
    if (!hasValidDeviceSignature(req, raw)) {
      sendUnauthorized(res);
      return;
    }
    const body = parseJsonBody(raw);
    const call = toolCallFrom(body.call);
    if (call === null) {
      sendJson(res, 400, { error: "call must be an object with string agentId and tool" });
      return;
    }
    let purpose: VetoPurpose | undefined;
    try {
      purpose = vetoPurposeFrom(body.purpose, call);
    } catch (err) {
      sendJson(res, 400, { error: err instanceof Error ? err.message : "invalid purpose" });
      return;
    }
    const id = `veto_${randomBytes(6).toString("hex")}`;
    // The window binds to the kill epoch in force NOW, in the server-side
    // record — a release from a dead epoch is refused below regardless of
    // which gateway retries it or whether that gateway restarted meanwhile.
    const window = new VetoWindow(call, killSwitch.epoch, {
      now,
      ...(purpose !== undefined ? { purpose } : {}),
    });
    vetoWindows.set(id, window);
    sendJson(res, 201, { id, status: window.state });
  }

  async function getVeto(req: IncomingMessage, res: ServerResponse, id: string): Promise<void> {
    const window = vetoWindows.get(id);
    if (!window) {
      sendJson(res, 404, { error: `no veto window "${id}"` });
      return;
    }
    // The open read stays status-only — anyone holding an id learns how the
    // question ended, nothing about its clock. An enrolled device (the
    // ladder, the owner app) additionally gets the deadline and the
    // delivered bit, so escalation paces itself off the window's own clock
    // instead of guessing (escalation DESIGN.md §3).
    const deviceRead = validDeviceIdFrom(req, await readRawBody(req)) !== null;
    const pacing = () =>
      deviceRead ? { deadline: window.deadlineAt, delivered: window.isDelivered } : {};
    let status: VetoWireStatus = window.tick();
    // A release authorizes exactly one run IN THE EPOCH IT WAS GRANTED. If a
    // kill happened after the window was registered — even one since
    // restored — the release is spent: `killed` alone flips back to false on
    // restore, but the epoch never does, and a pre-kill approval must not
    // execute in the post-kill world. An owner's veto is NOT overridden
    // here: "no" survives everything.
    if (status === "released" && window.killEpoch !== killSwitch.epoch) status = "spent";

    const grantsConfigured = opts.grantKey !== undefined && opts.grantKey !== "";
    const canonicalArgs = grantsConfigured ? grantEligibleArgs(window) : null;

    // A GRANT-ELIGIBLE window (a real merge) is authorized by ONE thing and
    // one thing only: the owner's ACTIVE approval (POST /veto/:id
    // decision=approve, owner-session authenticated). Silence never mints a
    // merge grant — the veto lane's "released-by-silence" is deliberately
    // NOT honored here, because the party that registered the window is
    // untrusted under the same-uid model (it can forge the gateway's device
    // secret), so signing its say-so would launder an unauthenticated
    // request into merge authority. An owner session is a token on the
    // owner's device, which the agent cannot reach; requiring it is what
    // makes the grant a real owner decision. See THREAT-MODEL.md.
    if (canonicalArgs !== null) {
      if (window.state === "vetoed") {
        sendJson(res, 200, { status: "vetoed" });
        return;
      }
      if (window.approvedBy === null) {
        // registered and shown to the owner, but not yet actively approved —
        // keep the gateway waiting; a merge never proceeds on silence
        sendJson(res, 200, { status: "pending", ...pacing() });
        return;
      }
      // Actively approved. Mint at most once, bound to the epoch in force AT
      // APPROVAL, with expiry anchored to the approval moment. A kill since
      // approval (or right now) makes it spent; a grant already issued makes
      // it spent; a late first read past the grant window makes it spent.
      if (grantedWindows.has(id)) {
        sendJson(res, 200, { status: "spent" });
        return;
      }
      const approvalEpoch = window.approvalEpoch ?? -1;
      if (killSwitch.killed || approvalEpoch !== killSwitch.epoch) {
        sendJson(res, 200, { status: "spent" });
        return;
      }
      const expiresAt = (window.approvedAt ?? now()) + grantTtlMs;
      if (now() >= expiresAt) {
        sendJson(res, 200, { status: "spent" });
        return;
      }
      grantedWindows.add(id);
      sendJson(res, 200, {
        status: "released",
        grant: mintGrant(id, window, canonicalArgs, approvalEpoch, expiresAt),
      });
      return;
    }

    // Not grant-eligible: the plain veto lane, unchanged — silence-release is
    // fine and mints no signed authority (no grant is ever minted here).
    sendJson(res, 200, { status, ...pacing() });
  }

  /**
   * The window's canonical args IFF the window may mint a MergeGrant: it
   * must have been REGISTERED under the one grant-eligible purpose, and its
   * arguments must parse under the closed merge schema. Everything else —
   * no purpose, a different purpose, arguments the schema refuses — returns
   * null and never mints, however merge-shaped the call may look. Purpose
   * is what the owner's approval was ABOUT; a signature must not outrun it.
   */
  function grantEligibleArgs(window: VetoWindow): string | null {
    const purpose = window.purpose;
    if (
      purpose === undefined ||
      purpose.connector !== GITHUB_CONNECTOR ||
      purpose.operation !== MERGE_PULL_REQUEST
    ) {
      return null;
    }
    const canonicalArgs = canonicalJson(window.call.args ?? {});
    try {
      parseMergePrArgs(canonicalArgs);
    } catch {
      return null;
    }
    return canonicalArgs;
  }

  /** Sign a single-use MergeGrant over the exact call the owner APPROVED.
   * `killEpoch` is the epoch at approval (not registration), so a kill
   * between registration and approval — or a window registered during a
   * kill — cannot produce authority that outlives the kill. */
  function mintGrant(
    windowId: string,
    window: VetoWindow,
    canonicalArgs: string,
    approvalEpoch: number,
    expiresAt: number,
  ): SignedMergeGrant {
    const purpose = window.purpose as VetoPurpose; // grantEligibleArgs guaranteed it
    const jti = `grant_${windowId}_${randomBytes(8).toString("hex")}`;
    // remember the mint (both directions) so the broker's grant-liveness
    // probe and atomic commit can be answered — and so a veto on this
    // window can find and revoke the grant
    mintedGrants.set(jti, windowId);
    windowToGrant.set(windowId, jti);
    return signMergeGrant(
      {
        v: 2,
        jti,
        agentId: window.call.agentId,
        tool: window.call.tool,
        connector: purpose.connector,
        operation: purpose.operation,
        policyVersion: purpose.policyVersion,
        canonicalArgs,
        callHash: sha256Hex(canonicalArgs),
        killEpoch: approvalEpoch,
        expiresAt,
      },
      opts.grantKey as string,
    );
  }

  function handler(req: IncomingMessage, res: ServerResponse): void {
    void route(req, res).catch((err) => {
      // never crash the process: a broken request gets an error response instead
      if (res.writableEnded) return;
      if (err instanceof BadJsonError) sendJson(res, 400, { error: err.message });
      else sendJson(res, 500, { error: "internal error" });
    });
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = req.method ?? "GET";
    const reqUrl = new URL(req.url ?? "/", "http://localhost");
    const path = reqUrl.pathname;
    const vetoMatch = /^\/veto\/([^/]+)$/.exec(path);
    const vetoSeenMatch = /^\/veto\/([^/]+)\/seen$/.exec(path);
    const approvalChallengeMatch = /^\/veto\/([^/]+)\/approval-challenge$/.exec(path);
    const restoreChallengeMatch = /^\/restore\/ceremony\/([^/]+)\/challenge$/.exec(path);
    const ceremonyMatch = /^\/restore\/ceremony\/([^/]+)$/.exec(path);

    if (method === "GET" && path === "/status") return getStatus(res);
    if (method === "GET" && path === "/kill-state") return getSignedKillState(reqUrl, res);
    if (method === "POST" && path === "/kill-state/commit") return postGrantCommit(req, res);
    if (method === "POST" && path === "/session/challenge") return postSessionChallenge(req, res);
    if (method === "POST" && path === "/session") return postSession(req, res);
    if (method === "POST" && approvalChallengeMatch) {
      return postApprovalChallenge(req, res, decodeURIComponent(approvalChallengeMatch[1]));
    }
    if (method === "POST" && path === "/kill") return postKill(req, res);
    if (method === "POST" && path === "/alert") return postAlert(req, res);
    if (method === "POST" && path === "/restore/ceremony") return postCeremonyStart(req, res);
    if (method === "POST" && restoreChallengeMatch) {
      return postRestoreChallenge(req, res, decodeURIComponent(restoreChallengeMatch[1]));
    }
    if (method === "GET" && ceremonyMatch) {
      return getCeremony(req, res, decodeURIComponent(ceremonyMatch[1]));
    }
    if (method === "POST" && path === "/restore") return postRestore(req, res);
    if (method === "POST" && path === "/veto") return postRegisterVeto(req, res);
    // literal routes outrun the :id capture — "pending" is a listing, not a window id
    if (method === "GET" && path === "/veto/pending") return getVetoPending(req, res);
    if (method === "POST" && vetoSeenMatch) {
      return postVetoSeen(req, res, decodeURIComponent(vetoSeenMatch[1]));
    }
    if (vetoMatch) {
      const id = decodeURIComponent(vetoMatch[1]);
      if (method === "POST") return postVeto(req, res, id);
      if (method === "GET") return getVeto(req, res, id);
    }
    sendJson(res, 404, { error: "not found" });
  }

  return { handler, killSwitch, vetoWindows };
}
