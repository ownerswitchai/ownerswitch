# @ownerswitchai/escalation — the ladder that confirms the owner saw the alert, so silence can mean something

The design is in [DESIGN.md](./DESIGN.md). This README is the runbook for
what is now implemented: the pure ladder engine, the push/SMS/voice
channels, and the always-on escalation service that ties them to the
control plane.

## Public code, private deployment

This repository is public and stays public. The line is drawn once, in
`src/config.ts`, and holds everywhere:

- **Public**: every line of code, the rung offsets, the request shapes,
  the webhook paths, the default ceilings. Anyone may read exactly how
  your phone gets called.
- **Private, environment-only**: the Twilio account SID/auth token, the
  phone numbers, the VAPID keypair, the device secret shared with the
  control plane. Nothing in this package reads secrets from a config
  file, accepts them on argv (visible to every same-host process), or
  writes them back to disk. Committing a `.env` is the only way to leak
  them — so don't have one in the repo; use your process manager's
  environment or a secret store.

The one runtime file is the push-subscription store
(`OWNERSWITCH_ESCALATION_STATE_FILE`, written `0600`): it holds the owner
app's push subscription — a capability to *send you notifications*, not an
account credential — and lives outside the repo.

## What runs where

```
agent → gateway → control plane (veto windows, kill state)
                       ▲    ▲
        device-signed  │    │  device-signed ack (owner app only)
        poll + veto    │    │
                  escalation service ── Twilio / Web Push
                       ▲
        signed webhooks│ (reply-1, press-1, receipts)
```

The service polls `GET /veto/pending` (device-signed), walks the ladder —
push at 0:00, SMS at 2:30, voice call at 5:00 — and relays any stop it
hears back as a device-signed `POST /veto/:id` with an honest channel
attribution. It **cannot** confirm delivery (that is the owner app's
`POST /veto/:id/seen`, on the app's own credential), cannot approve, and
cannot extend: its entire write surface is the deny direction.

## Environment

| variable | required | meaning |
| --- | --- | --- |
| `OWNERSWITCH_CONTROL_PLANE_URL` | no (default `http://127.0.0.1:4181`) | the control plane |
| `OWNERSWITCH_DEVICE_SECRET` | yes | shared device-HMAC secret |
| `OWNERSWITCH_ESCALATION_DEVICE_ID` | no (default `escalation`) | this service's device id |
| `OWNERSWITCH_VAPID_PUBLIC_KEY` / `_PRIVATE_KEY` / `_SUBJECT` | for push | mint with `ownerswitch-escalation vapid-keys` |
| `OWNERSWITCH_ESCALATION_STATE_FILE` | with push | 0600 push-subscription store |
| `OWNERSWITCH_TWILIO_ACCOUNT_SID` / `_AUTH_TOKEN` / `_FROM` | for SMS+voice | Twilio credentials and the provisioned number |
| `OWNERSWITCH_OWNER_PHONE` | with Twilio | the owner's E.164 number |
| `OWNERSWITCH_ESCALATION_WEBHOOK_BASE_URL` | with Twilio | public **https** base Twilio calls back |
| `OWNERSWITCH_ESCALATION_HOST` / `_PORT` | no (default `127.0.0.1:4190`) | webhook listener |
| `OWNERSWITCH_ESCALATION_POLL_MS` | no (default `5000`) | control-plane poll cadence |
| `OWNERSWITCH_ESCALATION_MAX_VOICE_PER_10MIN` / `_MAX_SMS_PER_HOUR` / `_MAX_DAILY_SPEND_USD` | no (defaults 2 / 6 / 5) | ceilings — caps stop spending and let windows go `held`, fail closed |

Channels assemble from what the environment provides: VAPID env → the
push rung; Twilio env → the SMS and voice rungs. Half a configuration
refuses to start; a configuration with no channel at all refuses too.
Email has no shipped channel yet and therefore no rung.

## Run

```bash
ownerswitch-escalation vapid-keys   # once: mint the push keypair
ownerswitch-escalation              # the service: poller + webhook server
```

Point your Twilio number's SMS webhook at
`${WEBHOOK_BASE_URL}/twilio/sms`. The voice call's press-1 action and the
SMS delivery receipts are advertised per-request. The owner app enrolls
its push subscription with a device-signed
`POST ${service}/push/subscription`.

Every inbound callback is signature-verified (`X-Twilio-Signature`)
before it is believed, and the only verb any of them can carry is
**stop** — a real OwnerSwitch call only ever offers to stop; any call
that asks you to press a key to approve, or to read back a code, is fake
by definition.
