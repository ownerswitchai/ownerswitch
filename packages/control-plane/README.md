# @ownerswitchai/control-plane — kill state, veto windows, 2GO restore

The one small, framework-free process every other component answers to.
Stops are cheap and attributable; starts are expensive and ceremonial.

## Surface (see `src/server.ts` for the full contract)

| route | auth | direction |
| --- | --- | --- |
| `POST /kill` | device-signed or loopback | stop — free forever |
| `POST /veto/:id` | owner session, or device-signed (deny-only relay) | stop |
| `POST /veto/:id/seen` | device-signed only | delivery ack (the permissive bit; 60 s response floor) |
| `GET /veto/pending`, `GET /veto/:id` | device-signed for pacing fields | read |
| `POST /veto/:id` `decision:approve` | owner session + passkey assertion | start (merge grant) |
| `POST /restore/ceremony` → `POST /restore` | owner session + passkey; 2GO cooldown | start — **the licensed act** |

## 2GO licensing (`src/license.ts`)

One press to stop is free, forever, for everyone — no stop path consults a
license, by construction (the only enforcement point in the codebase is
the restore-ceremony start, which answers **402** unlicensed). Two GOs to
start is the product: a TEAM/ENTERPRISE deployment provisions

```
OWNERSWITCH_LICENSE_PUBLIC_KEY_FILE=/etc/ownerswitch/license-verifying.pub.pem
OWNERSWITCH_LICENSE=osl1.<payload>.<signature>
```

Tokens are Ed25519-signed, verified offline — no phone-home, no
telemetry, air-gap friendly. An expired license keeps restoring for a
**72 h grace** (`RESTORE_GRACE_MS`): the paywall must never become a
ransom note over a killed fleet. Past the grace the fleet stays safely
stopped until renewal — fail closed, like everything else here.

Vendor tooling: `ownerswitch-license keygen | mint | inspect`
(`src/license-cli.ts`); key material travels by file path, never argv.
Dev/quickstart instances (no licensing option) are ungated.
