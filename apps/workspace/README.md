# @ownerswitchai/workspace-app — the owner's Workspace console (issue #44, console surface)

A local, deny-only control-room for a running OwnerSwitch deployment: live
kill state, the open veto windows with a one-click VETO, the enrolled-device
list, and a console event journal — the working subset of the Workspace
console mock. It **reads and stops**; it never approves, never restores,
never merges (those stay with the owner session + passkey lanes, by design).

```bash
OWNERSWITCH_CONTROL_PLANE_URL=http://127.0.0.1:4181 \
OWNERSWITCH_DEVICE_SECRET=… \
node apps/workspace/dist/cli.js        # serves http://127.0.0.1:4490
```

## Shape

Two layers, all new files, zero external runtime dependencies:

- **`src/` — the console server.** A small `node:http` process that serves
  `public/` (strict CSP: no inline script or style, `frame-ancestors 'none'`)
  and exposes an **allow-listed** `/api/*` proxy to the control plane. All
  credentials live here, from env, and never reach the browser:
  - `OWNERSWITCH_DEVICE_SECRET` (+ `OWNERSWITCH_DEVICE_ID`) signs the
    device-HMAC lane — `GET /veto/pending`, the veto `POST /veto/:id`, and
    kill attribution. Absent, those panels say "not configured" instead of
    pretending.
  - `OWNERSWITCH_OWNER_TOKEN` (an owner session bearer) authenticates
    `GET /devices`. Absent, the devices panel says so.
  Secrets come from env only — never argv, never a served config, never
  localStorage — per the repo convention (CONTRIBUTING.md).
- **`public/` — the browser console.** Vanilla HTML/CSS/JS in the mock's
  visual world. All logic that decides anything lives in
  `workspace-core.mjs`, a plain ESM module imported directly by the vitest
  suite (the `apps/owner` pattern); `app.js` is DOM glue. Every value that
  originated outside this page is assigned via `textContent`, never markup.

## Fail closed, stated exactly

- The kill-state poll treats **any** failure — network error, timeout,
  non-JSON, missing `epoch`, missing `killedAgents` — as
  **UNREACHABLE, rendered as killed**. The console never shows an optimistic
  ARMED it cannot prove; there is no silent default for a security-relevant
  field.
- The VETO button reports "STOPPED" only on the server's explicit
  `status: "vetoed"`; everything else stays retryable. A late response for a
  window the view no longer shows paints nothing.
- The pending list renders only entries that validate; malformed entries are
  counted and reported, never silently dropped, and a failed listing renders
  as "cannot list — fail closed", not as an empty happy list.

## Honest limits

- **Deny-only console, unauthenticated to its (loopback) callers.** The
  console server binds **literal loopback only** — the old
  `ALLOW_NONLOCAL` escape hatch is gone: with no caller auth and no TLS a
  LAN bind was an unauthenticated kill/veto proxy (post-merge audit).
  Remote access needs a real TLS+auth front in front of it. Anything that
  can reach loopback can stop things (veto, kill) and read what an
  enrolled surface could read (pending summaries, device labels).
- **A browser→console boundary guards every request** (post-merge audit):
  the Host header must be the console's own origin (DNS rebinding arrives
  under a foreign Host and is refused before any credential-backed
  upstream call), a present `Origin`/`Sec-Fetch-Site` must be same-origin,
  and mutations additionally require the `x-workspace-console: 1` header
  with an `application/json` content-type — an HTML form can produce
  neither, and a cross-origin fetch that tries preflights into a refusal.
  Scripting the API by hand means sending those two headers.
- **Nothing upstream-authored reaches the browser unshaped**: every /api
  response is rebuilt through a per-field allowlist (status, windows,
  devices, action answers), and error strings are stable local constants —
  never `Error.message`, never an upstream body's text, so no reflected
  header or echoed credential can transit the console. The control-plane
  URL itself is validated to a bare origin (no userinfo/path/query;
  plaintext http to literal loopback only) and only that origin is ever
  dialed or printed.
- **The journal is the console's own record**, labelled as such: what this
  console observed and did (state transitions, windows appearing/closing,
  vetoes, kills, poll failures). The control plane's authoritative audit
  trail has no read endpoint yet — see the PR's endpoint wishlist.
- **Countdowns trust the server's `deadline` against the local clock.** Skew
  shows up as a shifted countdown, never as a shifted decision — the server
  judges every deadline on its own clock.
- The mock's session/diff/merge-gate/settings panels are out of scope here:
  they need endpoints the control plane does not serve yet (same wishlist).
