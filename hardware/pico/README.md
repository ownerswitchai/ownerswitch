# 🔴 Hardware kill button — Raspberry Pi Pico

Reference firmware for a **physical** OwnerSwitch kill button: an industrial
emergency-stop wired to a Raspberry Pi Pico. Press it and the Pico prints
`KILL` over USB serial; the `ownerswitch-button` daemon reads that line and
sends a signed `POST /kill` to the control plane. **One press stops every
routed call.**

This is the hardware side of `packages/button`'s `serial` press source
(`ownerswitch-button --source serial`).

## Bill of materials

- **Raspberry Pi Pico** (RP2040 — the plain Pico is fine; no Wi-Fi needed).
- An **emergency-stop button** with a **normally-closed (NC)** contact
  (e.g. the common 22 mm mushroom "STOP" switch).
- Two jumper wires and a USB cable that carries **data** (not charge-only).

## Wiring — use the NC contact (fail-safe)

Wire the button's **normally-closed** contact between **GP15** and **GND**:

```
   e-stop NC contact
   ┌───────────────┐
   │               │
  GP15            GND        (GP15 is the corner pin next to the DEBUG header;
   (pin 20)      (pin 18)     GND is two pins in — check a Pico pinout diagram)
```

The firmware enables GP15's **internal pull-up**, so:

| State | Contact | GP15 | Result |
| --- | --- | --- | --- |
| At rest | NC **closed** → GP15 tied to GND | **LOW** | quiet |
| Pressed | NC **opens** | **HIGH** | `KILL` |
| Cable cut / unplugged | line floats up | **HIGH** | `KILL` (fail-safe) |

Using the **NC** contact is what makes it fail-safe: a cut wire or a yanked
button reads the same as a press. (A normally-open contact would fail *silent*
— don't use it.)

## Two modes — the host is inside the threat model

The host this button plugs into is exactly the machine the agent runs on, so
the button must not be **software-mutable from that host**. `boot.py` decides
the mode at power-up from a **dedicated maintenance jumper** — a physical act
the host cannot fake, and one that is never part of normal operation:

| | ARMED (normal) | MAINTENANCE |
| --- | --- | --- |
| How | plug in (no jumper) | jumper **GP14 → GND** (physical pins 19 → 18, right next to the button's pins), then plug in |
| `CIRCUITPY` drive | **hidden** — the host cannot rewrite the firmware | visible, for editing `code.py` |
| REPL console | **disabled** — the host cannot Ctrl-C the monitoring loop | enabled, for debugging |
| Serial devices | exactly **one** (the data channel) | two (console + data) |
| HID / MIDI | disabled | disabled |

**Why a separate jumper and not the e-stop:** GP15 HIGH is the fail-safe
*asserted* state — the button latched pressed, or a cut wire. Resetting or
power-cycling the Pico while KILL is legitimately asserted is a perfectly
normal event, and it must come back up **armed**, not with a writable drive
handed to the host it exists to stop. So the e-stop never selects the mode;
only the jumper does — and a broken or absent jumper fails to ARMED, the safe
direction. In maintenance mode the firmware still runs and still emits its
fail-safe `KILL`.

**Recovery, from cheapest to total:** need to edit the firmware → unplug,
jumper GP14→GND, replug (maintenance). Filesystem wedged beyond that → hold
**BOOTSEL** while plugging in, flash `flash_nuke.uf2` (full erase), then
re-flash CircuitPython and re-copy the firmware.

## Flash CircuitPython, then copy the firmware

1. Install **CircuitPython** on the Pico: hold **BOOTSEL** while plugging in the
   USB cable, then drag the CircuitPython `.uf2`
   (<https://circuitpython.org/board/raspberry_pi_pico/>) onto the `RPI-RP2`
   drive. The Pico reboots and reappears as a `CIRCUITPY` drive.
2. Copy **`boot.py`** and **`code.py`** from this directory onto `CIRCUITPY`.
3. Unplug and **wire the button** (previous section).
4. Re-plug (no jumper on GP14) → the Pico comes up **armed**: no drive, no
   console, one clean serial device. (To edit the firmware again: unplug,
   jumper **GP14 → GND**, re-plug → `CIRCUITPY` is back.)

## Connect it to OwnerSwitch

Find the Pico's serial device — in armed mode there is exactly one:

- **macOS:** `ls /dev/cu.usbmodem*`
- **Linux:** `ls /dev/ttyACM*`

Point the daemon at it:

```bash
# the device secret signs every kill request — never pass it as a flag
export OWNERSWITCH_DEVICE_SECRET='…'

ownerswitch-button \
  --url http://localhost:4000 \
  --device-id my-desk-button \
  --source serial \
  --device /dev/ttyACM0        # macOS: /dev/cu.usbmodemXXXX
```

Press the button → the daemon logs a confirmed kill. `Ctrl+C` exits.
(In maintenance mode two serial devices appear; the **data** channel — the
one carrying `READY`/`KILL` — is usually the second. Close any serial monitor
first; only one program can hold the port.)

## What the firmware emits

- `READY` once at power-up.
- `KILL` on every LOW→HIGH edge (press, or a broken/cut line), debounced ~30 ms.
- `KILL` again on boot if it comes up already HIGH (booted into the pressed or
  wire-broken state), and re-asserted every second while HIGH.

Emission is **non-blocking by construction**: writes carry a zero timeout and
run through a small outbox, so a slow, stalled, or absent reader can never
stall the monitoring loop (a stalled loop would defeat the boot-time
fail-safe). Partially delivered lines stay queued; while the line is HIGH the
1-second re-assert keeps offering a complete `KILL\n` until one lands. The
daemon matches the trigger line **exactly** (default `KILL`), de-dupes, and
`POST /kill` is idempotent — so re-asserts and missed lines are harmless. If
nothing is reading the port yet, `READY` may be missed; the daemon does not
depend on it. A silent disconnect is reported by the daemon but **not**
treated as a press, so a flaky USB cable doesn't kill on every hiccup; the
firmware's own fail-safe still prints a real `KILL` while it has power.

## Notes

- The plain **Pico** has no Wi-Fi/BLE — this button reaches OwnerSwitch over
  USB serial to a host running the daemon. That host is where policy and kill
  state live.
- The `--trigger` flag changes the line the daemon treats as a press if you
  adapt the firmware.
- Honest limit: armed mode stops the *host* from rewriting the firmware over
  USB. Anyone with **physical** access can fit the maintenance jumper —
  physical access has always been outside this boundary (they could as easily
  unplug the button, which at least fails safe).
