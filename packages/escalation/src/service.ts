import { randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { dirname } from "node:path";
import {
  canonicalTrustedStandingPath,
  DeviceStandingFileStore,
  enrolledOwnerDeviceFromSpki,
  signDeviceRequest,
  verifyOwnerDeviceSignature,
  type EnrolledOwnerDevice,
  type OwnerDeviceCredential,
} from "@ownerswitchai/control-plane";
import { createEmailChannel, createSesSender } from "./channels/email.js";
import { createTwilioSmsChannel, createTwilioVoiceChannel, TWILIO_PATHS } from "./channels/twilio.js";
import { createWebPushChannel, type PushSubscriptionJson } from "./channels/webpush.js";
import { LadderEngine } from "./ladder.js";
import type { EscalationEnvConfig } from "./config.js";
import type { Channel, ChannelEvent, ChannelKind, LadderAction } from "./types.js";

/**
 * The escalation service — the ladder's edge, and its own always-on
 * process (DESIGN.md §1): it holds the provider credentials and the
 * webhook surface, and talks to the control plane only through the same
 * device-signed HTTP every other component uses. The control plane stays
 * the one small framework-free process; nothing in here runs inside it.
 *
 * The engine decides, this file performs. Everything imported from
 * ladder.ts is pure; this file owns the clocks, the sockets, the state
 * file, and the honest logging. Its ENTIRE write surface toward the veto
 * state machine is the device-signed veto relay — the deny direction. It
 * cannot ack (`/veto/:id/seen` is the owner app's, on the app's own
 * credential), cannot approve, cannot extend.
 */

interface PendingWindow {
  id: string;
  status: "pending" | "extended";
  agentId: string;
  tool: string;
  deadline: number;
  delivered: boolean;
}

export interface EscalationServiceOptions {
  config: EscalationEnvConfig;
  /** injectable for tests; replaces the channels built from config */
  channels?: Partial<Record<ChannelKind, Channel>>;
  fetchImpl?: typeof fetch;
  now?: () => number;
  /** honest, terse logging; default console.error. Never carries secrets. */
  log?: (line: string) => void;
}

export interface EscalationService {
  /** one poll + engine tick + action execution; the run loop calls this */
  tickOnce(): Promise<void>;
  /** plug into http.createServer — the webhook + enrollment surface */
  webhookHandler: (req: IncomingMessage, res: ServerResponse) => void;
  /** the currently enrolled push subscription, if any (tests, doctor) */
  subscription(): PushSubscriptionJson | null;
}

const MAX_WEBHOOK_BODY_BYTES = 64 * 1024;

export function createEscalationService(opts: EscalationServiceOptions): EscalationService {
  const cfg = opts.config;
  const now = opts.now ?? Date.now;
  const doFetch = opts.fetchImpl ?? fetch;
  const log = opts.log ?? ((line: string) => console.error(`[ownerswitch-escalation] ${line}`));

  // Enrolled owner-app device public keys — the credential push enrollment is
  // gated on. Built once; a bad key would have failed the config load. The
  // dev_ namespace is the ceremony registry's (same rule as the control
  // plane): a static key squatting on it could shadow an enrolled identity.
  const ownerDevices = new Map<string, EnrolledOwnerDevice>();
  for (const [deviceId, spki] of Object.entries(cfg.ownerDeviceKeys ?? {})) {
    if (deviceId.startsWith("dev_")) {
      throw new Error(
        `owner device key id "${deviceId}" uses the "dev_" namespace reserved for ` +
          "ceremony-enrolled devices — rename it so the two identity spaces cannot collide",
      );
    }
    ownerDevices.set(deviceId, enrolledOwnerDeviceFromSpki(deviceId, spki));
  }

  // The SHARED durable standing registry the control plane writes (and
  // initializes at ITS boot with the full active snapshot). Re-read on every
  // owner-device decision here (the file is tiny, the operations are rare):
  // a revocation on the control plane severs THIS service's surfaces at the
  // very next request, without any cross-process notification channel. No
  // configured store (dev, no owner devices) → standing is not consulted.
  // With a store configured, ONLY an explicit active record is trust:
  //  - ABSENT registry → untrusted (the control plane has never initialized
  //    it — a wrong path or an empty provisioned directory must read as "not
  //    wired yet", never as "everyone active");
  //  - a device with NO record → untrusted (enrollment lands in the registry
  //    at the control plane's boot migration, not by implication here);
  //  - CORRUPT → untrusted, everyone.
  // Fail closed in every branch: alerts stop, stop paths (SMS, voice, the
  // veto relay) are untouched.
  // The path is canonicalized and its REAL ancestry proven trusted before
  // first use — the reader must not follow a swapped ancestor to an
  // attacker's registry any more than the writer may (the distinct-UID
  // model names the control plane's uid explicitly via config).
  // The reader enforces the SAME load-time boundary as the writer: the leaf
  // must be owned by root / this process / the operator-named CP uid, and be
  // exactly 0600, or 0640 matching the SAME configured read-only gid the CP
  // publishes with (OWNERSWITCH_OWNER_DEVICE_STANDING_GID on both services).
  // Anything else loads corrupt → everyone untrusted.
  const ourUid = typeof process.getuid === "function" ? process.getuid() : 0;
  const standingStore =
    cfg.ownerDeviceStandingFile !== undefined
      ? new DeviceStandingFileStore(
          canonicalTrustedStandingPath(cfg.ownerDeviceStandingFile, {
            ...(cfg.ownerDeviceStandingTrustedUid !== undefined
              ? { alsoTrustUids: [cfg.ownerDeviceStandingTrustedUid] }
              : {}),
            ...(cfg.unsafeAllowUntrustedStandingPathForTests === true
              ? { unsafeAllowUntrustedAncestryForTests: true }
              : {}),
          }),
          {
            ...(cfg.ownerDeviceStandingGid !== undefined ? { group: cfg.ownerDeviceStandingGid } : {}),
            trustedOwnerUids: [
              0,
              ourUid,
              ...(cfg.ownerDeviceStandingTrustedUid !== undefined ? [cfg.ownerDeviceStandingTrustedUid] : []),
            ],
          },
        )
      : null;
  function deviceInGoodStanding(deviceId: string): boolean {
    if (standingStore === null) return true;
    const loaded = standingStore.load();
    if (loaded.outcome !== "loaded") return false; // absent or corrupt: no trust without a registry
    if (!Object.hasOwn(loaded.state.devices, deviceId)) return false;
    return loaded.state.devices[deviceId].revokedAt === null;
  }

  // CEREMONY-ENROLLED (dev_*) devices: the control plane exports their
  // cheap-lane PUBLIC key into the shared standing file (schema v2, `spki`
  // per entry) precisely so THIS distinct-UID process can authenticate them
  // without ever touching the control-plane-private registry. Resolution
  // order mirrors the control plane's: the static keys file first, then a
  // fresh standing-file read — generation/revokedAt always come from the
  // load, only the PARSED key is cached (keyed by the SPKI string, so a
  // changed entry can never serve a stale key). Every SPKI goes through the
  // same strict parser as the keys file (enrolledOwnerDeviceFromSpki); an
  // entry it refuses resolves nothing. Fail direction everywhere: no store,
  // no file, corrupt file, unknown id, bad SPKI → undefined → 401.
  const enrolledKeyCache = new Map<string, { spki: string; device: EnrolledOwnerDevice }>();
  function resolveOwnerDevice(deviceId: string): EnrolledOwnerDevice | undefined {
    const provisioned = ownerDevices.get(deviceId);
    if (provisioned !== undefined) return provisioned;
    if (standingStore === null) return undefined;
    const loaded = standingStore.load();
    if (loaded.outcome !== "loaded") return undefined;
    if (!Object.hasOwn(loaded.state.devices, deviceId)) return undefined;
    const entry = loaded.state.devices[deviceId];
    if (entry.spki === undefined) return undefined; // static entry: its key lives in the keys file
    const cached = enrolledKeyCache.get(deviceId);
    if (cached !== undefined && cached.spki === entry.spki) {
      cached.device.generation = entry.generation;
      cached.device.revokedAt = entry.revokedAt;
      return cached.device;
    }
    let device: EnrolledOwnerDevice;
    try {
      device = enrolledOwnerDeviceFromSpki(deviceId, entry.spki);
    } catch {
      return undefined; // an SPKI the strict parser refuses is no identity
    }
    device.generation = entry.generation;
    device.revokedAt = entry.revokedAt;
    enrolledKeyCache.set(deviceId, { spki: entry.spki, device });
    return device;
  }
  const ownerDeviceResolver = { get: (deviceId: string) => resolveOwnerDevice(deviceId) };
  /** true when ANY owner-device credential source is wired (keys file, or standing entries with keys). */
  function ownerDeviceLaneWired(): boolean {
    if (ownerDevices.size > 0) return true;
    if (standingStore === null) return false;
    const loaded = standingStore.load();
    if (loaded.outcome !== "loaded") return false;
    return Object.values(loaded.state.devices).some((entry) => entry.spki !== undefined);
  }

  /* ---------------- push subscription store (0600, atomic) ------------- */

  let storedSubscription: PushSubscriptionJson | null = null;
  // who enrolled the subscription — a revocation of THAT device deactivates
  // it (null on legacy stores written before this field existed)
  let subscriptionEnrolledBy: string | null = null;
  loadSubscription();

  function loadSubscription(): void {
    if (cfg.stateFile === undefined) return;
    try {
      const parsed: unknown = JSON.parse(readFileSync(cfg.stateFile, "utf8"));
      const record = parsed as { subscription?: unknown; enrolledBy?: unknown };
      if (isSubscription(record.subscription)) {
        storedSubscription = record.subscription;
        subscriptionEnrolledBy = typeof record.enrolledBy === "string" ? record.enrolledBy : null;
      }
    } catch {
      /* absent or unreadable: no subscription until re-enrolled */
    }
  }

  /**
   * The subscription the dispatcher may actually SEND to. Under a standing
   * regime (a registry is configured), a subscription is active ONLY when it
   * names its enrolling device AND that device is in good standing:
   *  - the enrolling device was revoked → inactive (the lost phone must not
   *    keep receiving decision-critical alerts);
   *  - a LEGACY record with no enrolledBy → inactive too. It cannot be tied
   *    to any device, so a revocation can never sever it — waiting for the
   *    lost phone to "voluntarily re-enroll" is not a revocation story. The
   *    owner's app re-enrolls on its next open (subscribeAndEnroll is called
   *    on every launch), which stamps the record and reactivates push.
   * With no registry configured (dev), the stored subscription is served
   * as-is — there is no standing to consult.
   */
  function activeSubscription(): PushSubscriptionJson | null {
    if (storedSubscription === null) return null;
    if (standingStore === null) return storedSubscription;
    if (subscriptionEnrolledBy === null) return null; // legacy: fail closed
    return deviceInGoodStanding(subscriptionEnrolledBy) ? storedSubscription : null;
  }

  function persistSubscription(sub: PushSubscriptionJson, enrolledBy: string): void {
    if (cfg.stateFile === undefined) return;
    // atomic replace, private from birth: the subscription is a send
    // capability, and a half-written store must not exist even briefly
    mkdirSync(dirname(cfg.stateFile), { recursive: true, mode: 0o700 });
    const tmp = `${cfg.stateFile}.${randomBytes(6).toString("hex")}.tmp`;
    writeFileSync(tmp, JSON.stringify({ subscription: sub, enrolledBy }, null, 2), { mode: 0o600 });
    chmodSync(tmp, 0o600);
    renameSync(tmp, cfg.stateFile);
  }

  function isSubscription(value: unknown): value is PushSubscriptionJson {
    if (typeof value !== "object" || value === null) return false;
    const { endpoint, keys } = value as Record<string, unknown>;
    if (typeof endpoint !== "string" || !endpoint.startsWith("https://")) return false;
    if (typeof keys !== "object" || keys === null) return false;
    const { p256dh, auth } = keys as Record<string, unknown>;
    return typeof p256dh === "string" && p256dh !== "" && typeof auth === "string" && auth !== "";
  }

  /* ---------------- channels ------------------------------------------ */

  const channels = new Map<ChannelKind, Channel>();
  if (cfg.vapid !== undefined) {
    channels.set(
      "push",
      createWebPushChannel({
        vapidPublicKey: cfg.vapid.publicKey,
        vapidPrivateKey: cfg.vapid.privateKey,
        subject: cfg.vapid.subject,
        getSubscription: activeSubscription,
        fetch: doFetch,
        now,
      }),
    );
  }
  if (cfg.twilio !== undefined) {
    const twilioCfg = {
      ...cfg.twilio,
      webhookBaseUrl: cfg.webhookBaseUrl as string,
      fetch: doFetch,
      now,
    };
    channels.set("sms", createTwilioSmsChannel(twilioCfg));
    channels.set("voice", createTwilioVoiceChannel(twilioCfg));
  }
  if (cfg.email !== undefined) {
    channels.set(
      "email",
      createEmailChannel({
        from: cfg.email.from,
        to: cfg.email.to,
        ownerAppUrl: cfg.email.ownerAppUrl,
        sendEmail: createSesSender({ ...cfg.email.ses, fetch: doFetch }),
        now,
      }),
    );
  }
  for (const [kind, channel] of Object.entries(opts.channels ?? {})) {
    if (channel !== undefined) channels.set(kind as ChannelKind, channel);
  }

  const engine = new LadderEngine({
    rungs: cfg.rungs.filter((r) => channels.has(r.channel)),
    limits: cfg.limits,
  });

  /* ---------------- device-signed control-plane client ----------------- */

  async function deviceRequest(path: string, method: "GET" | "POST", body = ""): Promise<Response> {
    const timestamp = now();
    const nonce = randomBytes(12).toString("hex");
    return doFetch(new URL(path, cfg.controlPlaneUrl), {
      method,
      cache: "no-store",
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store, no-cache",
        "x-device-id": cfg.device.id,
        "x-device-timestamp": String(timestamp),
        "x-device-nonce": nonce,
        "x-device-signature": signDeviceRequest(
          { deviceId: cfg.device.id, timestamp, nonce },
          body,
          cfg.device.secret,
        ),
      },
      ...(method === "POST" ? { body } : {}),
    });
  }

  async function listPending(): Promise<PendingWindow[] | null> {
    try {
      const res = await deviceRequest("/veto/pending", "GET");
      if (!res.ok) {
        log(`control plane refused /veto/pending: HTTP ${res.status}`);
        return null;
      }
      const parsed = (await res.json()) as { windows?: unknown };
      return Array.isArray(parsed.windows) ? (parsed.windows as PendingWindow[]) : [];
    } catch {
      // unreachable control plane: DELIVERY stalls, which degrades toward
      // held — the fail-closed direction. Nothing to do but say so.
      log("control plane unreachable — ladder paused this tick");
      return null;
    }
  }

  async function relayVeto(windowId: string, attribution: string): Promise<void> {
    const body = JSON.stringify({ decision: "veto", attribution });
    try {
      const res = await deviceRequest(`/veto/${encodeURIComponent(windowId)}`, "POST", body);
      if (!res.ok && res.status !== 409) {
        log(`veto relay for ${windowId} refused: HTTP ${res.status}`);
        return;
      }
      log(`relayed stop for ${windowId} (${attribution})`);
    } catch {
      log(`veto relay for ${windowId} failed — will retry while the window stays open`);
      pendingRelays.push({ windowId, attribution });
    }
  }

  /* ---------------- reconcile + tick ----------------------------------- */

  /** window ids the engine currently knows, to detect closures */
  const tracked = new Set<string>();
  /** relays that failed transport; retried each tick (idempotent server-side) */
  let pendingRelays: Array<{ windowId: string; attribution: string }> = [];

  async function tickOnce(): Promise<void> {
    const listing = await listPending();
    if (listing !== null) {
      const openIds = new Set(listing.map((w) => w.id));
      for (const id of tracked) {
        if (!openIds.has(id)) {
          engine.windowClosed(id);
          tracked.delete(id);
        }
      }
      for (const w of listing) {
        if (!tracked.has(w.id)) {
          engine.windowOpened(w.id, `"${w.tool}"`, w.deadline);
          tracked.add(w.id);
        }
        engine.windowDeadline(w.id, w.deadline);
        if (w.delivered) engine.windowDelivered(w.id);
      }
    }

    const retries = pendingRelays.filter((r) => tracked.has(r.windowId));
    pendingRelays = [];
    for (const retry of retries) await relayVeto(retry.windowId, retry.attribution);

    for (const action of engine.tick(now())) await perform(action);
  }

  async function perform(action: LadderAction): Promise<void> {
    if (action.type === "send") {
      const channel = channels.get(action.channel);
      if (channel === undefined) return; // rungs are filtered to built channels
      try {
        const attempt = await channel.send(action.alert);
        log(
          `sent ${action.channel} alert covering ${attempt.windowIds.length} window(s)` +
            (attempt.providerRef !== undefined ? ` ref=${attempt.providerRef}` : ""),
        );
      } catch (err) {
        // one rung failing must not stop the ladder — the next rung is the
        // retry story, and total failure degrades to held (fail closed)
        log(`${action.channel} send failed: ${err instanceof Error ? err.message : "error"}`);
      }
      return;
    }
    if (action.type === "relay-veto") {
      for (const windowId of action.windowIds) await relayVeto(windowId, action.attribution);
      return;
    }
    log(`stand-down (${action.reason}) for ${action.windowIds.length} window(s)`);
  }

  /* ---------------- webhook + enrollment surface ------------------------ */

  function webhookHandler(req: IncomingMessage, res: ServerResponse): void {
    void routeWebhook(req, res).catch(() => {
      if (!res.writableEnded) send(res, 500, "text/plain", "error");
    });
  }

  async function routeWebhook(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = req.method ?? "GET";
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    const rawBody = await readBody(req);
    if (rawBody === null) {
      send(res, 413, "text/plain", "body too large");
      return;
    }

    if (method === "GET" && path === "/healthz") {
      send(res, 200, "application/json", JSON.stringify({ ok: true, active: engine.active }));
      return;
    }

    // enrollment: the owner app registers its push subscription, signed with
    // the OWNER APP's ASYMMETRIC device key (ECDSA P-256) — NOT the fleet
    // device secret this service holds. Enrollment picks who receives every
    // future alert, so gating it on the fleet secret would let any
    // fleet-secret holder redirect the owner's push channel to their own
    // endpoint; an asymmetric signature the service can only VERIFY (never
    // produce) closes that. Absent an enrolled owner device, enrollment is
    // simply unavailable (501).
    if (method === "POST" && path === "/push/subscription") {
      if (!ownerDeviceLaneWired()) {
        send(
          res,
          501,
          "application/json",
          JSON.stringify({
            error:
              "push enrollment is not available: no owner-app device credential source is wired " +
              "(neither OWNERSWITCH_OWNER_DEVICE_KEYS_FILE nor ceremony-enrolled entries in the " +
              "shared standing file)",
          }),
        );
        return;
      }
      const enrolledBy = verifyOwnerDeviceSignature(
        ownerCredentialFrom(req),
        (req.method ?? "").toUpperCase(),
        req.url ?? "",
        rawBody,
        ownerDeviceResolver,
        { now, seenNonces },
      );
      if (enrolledBy === null) {
        send(res, 401, "application/json", JSON.stringify({ error: "unauthorized" }));
        return;
      }
      // The signature proves possession of the enrolled key; STANDING proves
      // the control plane still trusts it. Re-read from the shared registry
      // on every enrollment, so a revoked (stolen) phone cannot redirect the
      // owner's alert channel even though this process never saw the revoke.
      if (!deviceInGoodStanding(enrolledBy)) {
        send(res, 403, "application/json", JSON.stringify({ error: "device revoked — enrollment refused" }));
        return;
      }
      let sub: unknown;
      try {
        sub = (JSON.parse(rawBody) as Record<string, unknown>).subscription;
      } catch {
        send(res, 400, "application/json", JSON.stringify({ error: "malformed JSON" }));
        return;
      }
      if (!isSubscription(sub)) {
        send(res, 400, "application/json", JSON.stringify({ error: "subscription must be {endpoint: https-url, keys: {p256dh, auth}}" }));
        return;
      }
      storedSubscription = sub;
      subscriptionEnrolledBy = enrolledBy;
      persistSubscription(sub, enrolledBy);
      log("push subscription enrolled");
      send(res, 200, "application/json", JSON.stringify({ ok: true }));
      return;
    }

    // Twilio callbacks: verification lives INSIDE the channel that owns the
    // provider relationship; this edge only reconstructs the advertised URL
    const twilioPaths = Object.values(TWILIO_PATHS) as string[];
    if (method === "POST" && twilioPaths.includes(path)) {
      const events = collectTwilioEvents(path, rawBody, req);
      for (const event of events) engine.channelEvent(event);
      if (events.length > 0) {
        // a stop should not wait for the next poll tick — relay immediately
        for (const action of engine.tick(now())) await perform(action);
      }
      respondTwiml(res, path, events);
      return;
    }

    send(res, 404, "text/plain", "not found");
  }

  function collectTwilioEvents(path: string, rawBody: string, req: IncomingMessage): ChannelEvent[] {
    if (cfg.webhookBaseUrl === undefined) return [];
    const callback = {
      rawBody,
      headers: Object.fromEntries(
        Object.entries(req.headers).map(([k, v]) => [k, Array.isArray(v) ? (v[0] ?? "") : (v ?? "")]),
      ),
      url: `${cfg.webhookBaseUrl}${path}`,
    };
    const events: ChannelEvent[] = [];
    for (const kind of ["sms", "voice"] as const) {
      const channel = channels.get(kind);
      if (channel !== undefined) events.push(...channel.handleCallback(callback));
    }
    return events;
  }

  function respondTwiml(res: ServerResponse, path: string, events: ChannelEvent[]): void {
    const stopped = events.some((e) => e.type === "veto");
    if (path === TWILIO_PATHS.voiceKey) {
      const say = stopped
        ? "Stopped. Nothing will run. Goodbye."
        : "Nothing stopped. Goodbye.";
      send(
        res,
        200,
        "text/xml",
        `<?xml version="1.0" encoding="UTF-8"?><Response><Say>${say}</Say></Response>`,
      );
      return;
    }
    // inbound SMS / status callbacks want an empty TwiML ack
    send(res, 200, "text/xml", `<?xml version="1.0" encoding="UTF-8"?><Response/>`);
  }

  /** The owner-app device credential from the request headers, for verification. */
  function ownerCredentialFrom(req: IncomingMessage): OwnerDeviceCredential {
    const header = (name: string) => {
      const value = req.headers[name];
      return Array.isArray(value) ? value[0] : value;
    };
    return {
      deviceId: header("x-device-id") ?? "",
      timestamp: Number(header("x-device-timestamp") ?? NaN),
      nonce: header("x-device-nonce") ?? "",
      signature: header("x-device-signature") ?? "",
    };
  }
  const seenNonces = new Map<string, number>();

  async function readBody(req: IncomingMessage): Promise<string | null> {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
      size += (chunk as Buffer).length;
      if (size > MAX_WEBHOOK_BODY_BYTES) return null;
      chunks.push(chunk as Buffer);
    }
    return Buffer.concat(chunks).toString("utf8");
  }

  function send(res: ServerResponse, status: number, type: string, body: string): void {
    res.writeHead(status, { "content-type": type, "cache-control": "no-store, max-age=0" });
    res.end(body);
  }

  // The accessor answers what the PUSH CHANNEL would actually use — standing
  // included — so the doctor and tests see the same truth the dispatcher does:
  // a subscription whose enrolling device was revoked (or a legacy record
  // that names no device) reads as none.
  return { tickOnce, webhookHandler, subscription: activeSubscription };
}
