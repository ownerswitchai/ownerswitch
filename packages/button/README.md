# @ownerswitchai/button

V0 physical kill button — a small daemon that turns a hardware key press
into a signed `POST /kill` against the control plane.

The V0 hardware story: any USB button that enumerates as a keyboard (most
cheap "big red buttons" do) — the daemon listens on stdin in raw mode for a
configurable key. For testing without hardware there is a loopback HTTP
source (`POST /press`).

## Guarantees

- **A press never gets lost.** A failed `POST /kill` retries with backoff
  (200/400/800 ms, then every 2 s) forever, logging loudly on every attempt.
- **Bounce is not intent.** Presses within 1 s collapse into one kill —
  unless an attempt already failed, in which case a press always re-fires
  immediately with the backoff reset. `POST /kill` is idempotent, so the
  daemon errs toward sending again.
- **Every attempt is signed fresh** with `signDeviceRequest` (single-use
  nonce, timestamp inside the skew window), so the control plane attributes
  the kill to this device: source `"button"`, no `unauthenticated` flag.

## CLI

```bash
ownerswitch-button --url http://localhost:4000 --device-id big-red-button \
  --secret $OWNERSWITCH_DEVICE_SECRET --source keyboard --key space
```

`--source http` starts the loopback press endpoint instead
(default port 5455 — "KILL" on a phone keypad):

```bash
curl -X POST http://127.0.0.1:5455/press
```

On a successful kill the CLI prints the control plane's audit confirmation
(`GET /status`: reason and timestamp).

## Demo

From the repo root, control plane + button in one process:

```bash
pnpm demo:button
```
