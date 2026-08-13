# Device-standing registry — deployment & activation checklist

The durable standing registry (`device-standing.ts`) is what makes an
owner-device revocation survive a control-plane restart. Its file is
POSITIVE AUTHORIZATION STATE: whoever can rewrite `revokedAt: null`
re-activates a stolen phone. This checklist is the operational half of the
code's guarantees — the live owner-device release-on-silence lane MUST NOT
be activated until every item below has been verified on the actual
deployment host.

## Environment

Control plane (`packages/mcp` launcher):

| Variable | Meaning |
| --- | --- |
| `OWNERSWITCH_OWNER_DEVICE_KEYS_FILE` | `{deviceId: SPKI PEM}` — enrolling this ARMS the lane; leave unset/empty until this checklist passes |
| `OWNERSWITCH_OWNER_DEVICE_STANDING_FILE` | absolute path of the registry; REQUIRED whenever keys are enrolled |
| `OWNERSWITCH_OWNER_DEVICE_STANDING_GROUP_READABLE` | `1` for the distinct-UID model (0640); all-or-nothing with the GID below |
| `OWNERSWITCH_OWNER_DEVICE_STANDING_GID` | the shared read-only group's numeric gid; all-or-nothing with the flag above |

Escalation service (same registry, read-only):

| Variable | Meaning |
| --- | --- |
| `OWNERSWITCH_OWNER_DEVICE_STANDING_FILE` | the SAME path the control plane persists to; REQUIRED whenever keys are enrolled |
| `OWNERSWITCH_OWNER_DEVICE_STANDING_TRUSTED_UID` | the control plane's uid (distinct-UID model) — names the trusted owner of the path's ancestry and the file |
| `OWNERSWITCH_OWNER_DEVICE_STANDING_GID` | the SAME gid the control plane publishes with |

Two supported models, nothing in between:

- **Same-user**: CP and escalation run as one uid → registry 0600, no
  GROUP_READABLE / GID / TRUSTED_UID anywhere.
- **Distinct-UID** (the credential-isolation production model): CP owns and
  writes; escalation reads via a dedicated read-only group → 0640 + GID on
  BOTH services, TRUSTED_UID on the escalation side.

## Filesystem layout (distinct-UID model)

```
# one-time provisioning, as root
groupadd ownerswitch-standing
usermod -aG ownerswitch-standing <escalation-user>
mkdir -p /var/lib/ownerswitch
chown <cp-user>:ownerswitch-standing /var/lib/ownerswitch
chmod 2750 /var/lib/ownerswitch          # setgid keeps the group on new files
```

The code enforces at boot (refusing to start otherwise): absolute path
outside the working directory; every REAL ancestor owned by root / the
service user / the named trusted uid and neither group- nor world-writable;
and at every load: the leaf owned by a trusted uid, mode EXACTLY 0600 or
EXACTLY 0640-with-matching-gid, anything else = corrupt = everyone revoked.

## Cross-UID verification (MANDATORY before live activation)

CI runs single-uid, so this MUST be exercised manually on the deployment
host. All six checks, in order:

1. **CP boot init** — start the control plane with keys + standing file
   configured. Verify the registry exists, mode `0640`, owner `<cp-user>`,
   group `ownerswitch-standing` (`ls -l /var/lib/ownerswitch/`).
2. **Escalation read** — start the escalation service as `<escalation-user>`
   with the same STANDING_FILE + TRUSTED_UID + GID. Verify it boots and a
   push enrollment by an active device succeeds (HTTP 200).
3. **Escalation cannot write** — as `<escalation-user>`:
   `touch /var/lib/ownerswitch/standing.json` and appending to the file must
   both fail with EACCES.
4. **Revocation propagates** — `POST /devices/<id>/revoke` on the CP, then
   verify the escalation service refuses that device's next enrollment (403)
   and `subscription()` reports none, WITHOUT restarting either service.
5. **Restart survival** — restart the CP; the revoked device must still be
   401 on `/veto/:id/detail`.
6. **Wrong-GID fail-closed** — `chgrp <other-group> standing.json`, then
   verify BOTH services treat the registry as corrupt (CP: all devices
   revoked at next boot; escalation: every device untrusted at next
   request). Restore the group afterwards and re-run check 2.

## Failure semantics worth knowing on-call

- A revoke whose persist fails answers **503** and engages the DURABLE kill
  switch: the next boot comes up killed even if the registry still says the
  phone is active. Recovery: repair the path, re-run the (idempotent)
  revoke, then restore via 2GO.
- Deleting the standing file does not reset anything: the `.initialized`
  marker makes a missing file load as corrupt (everyone revoked).
- A corrupt registry never blocks a STOP: kill, veto relay, SMS/voice paths
  are untouched — only the permissive ack lane dies.
