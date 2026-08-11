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

## Flash CircuitPython, then copy the firmware

1. Install **CircuitPython** on the Pico: hold **BOOTSEL** while plugging in the
   USB cable, then drag the CircuitPython `.uf2`
   (<https://circuitpython.org/board/raspberry_pi_pico/>) onto the `RPI-RP2`
   drive. The Pico reboots and reappears as a `CIRCUITPY` drive.
2. Copy **`boot.py`** and **`code.py`** from this directory onto `CIRCUITPY`.
3. Re-plug the Pico (a fresh power-up so `boot.py` takes effect). It now
   exposes two USB serial devices: the REPL **console** and a dedicated
   **data** channel — the daemon reads the data channel.

## Connect it to OwnerSwitch

Find the Pico's serial device(s):

- **macOS:** `ls /dev/cu.usbmodem*`
- **Linux:** `ls /dev/ttyACM*`

Two devices appear (console + data). The **data** channel is the one that
carries only `READY`/`KILL` — usually the second of the pair. Point the daemon
at it:

```bash
# the device secret signs every kill request — never pass it as a flag
export OWNERSWITCH_DEVICE_SECRET='…'

ownerswitch-button \
  --url http://localhost:4000 \
  --device-id my-desk-button \
  --source serial \
  --device /dev/ttyACM1        # macOS: /dev/cu.usbmodemXXXX (the data channel)
```

Press the button → the daemon logs a confirmed kill. `Ctrl+C` exits.
Close any serial monitor (Mu, `screen`, the Arduino monitor) first — only one
program can hold the port.

## What the firmware emits

- `READY` once at power-up.
- `KILL` on every LOW→HIGH edge (press, or a broken/cut line), debounced ~30 ms.
- `KILL` again on boot if it comes up already HIGH (booted into the pressed or
  wire-broken state), and re-asserted every second while HIGH.

The daemon matches the trigger line **exactly** (default `KILL`) and de-dupes,
and `POST /kill` is idempotent — so a re-assert or a missed line is harmless.
A silent disconnect is reported by the daemon but **not** treated as a press,
so a flaky USB cable doesn't kill on every hiccup; the firmware's own
fail-safe still prints a real `KILL` while it has power.

## Notes

- The plain **Pico** has no Wi-Fi/BLE — this button reaches OwnerSwitch over
  USB serial to a host running the daemon. That host is where policy and kill
  state live.
- The `--trigger` flag changes the line the daemon treats as a press if you
  adapt the firmware.
