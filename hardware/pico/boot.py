# boot.py — OwnerSwitch kill button (Raspberry Pi Pico, CircuitPython)
#
# Two jobs, both about the trust boundary between the button and the host it
# is meant to stop. Runs once at power-on / reset, before USB enumerates.
#
# 1. Expose a DEDICATED USB serial "data" channel for the KILL signal.
# 2. Decide the mode from a DEDICATED maintenance jumper — deliberately NOT
#    from the e-stop line. GP15 HIGH is the fail-safe ASSERTED state (button
#    latched pressed, or a broken wire): a Pico reset or power-cycle while
#    KILL is legitimately asserted is a NORMAL event, and it must come back
#    up ARMED, not with a writable drive handed to the hostile host. So the
#    e-stop can never select the mode; only the jumper can.
#
#    ARMED (normal): no jumper.
#      - CIRCUITPY mass storage DISABLED: the host this button plugs into is
#        exactly the machine the agent runs on — a writable firmware volume
#        would let a compromised host rewrite code.py and make the next
#        physical press silent.
#      - REPL console DISABLED: a console lets the host Ctrl-C the firmware
#        into the REPL, stopping the monitoring loop — same failure class.
#      - Exactly one serial device appears: the data channel.
#
#    MAINTENANCE: jumper GP14 (physical pin 19) to GND (physical pin 18 — the
#    pin right next to it, the same GND the button uses) BEFORE plugging in.
#      - CIRCUITPY drive and REPL console stay enabled for editing/debugging.
#      - Grounding a bare header pin takes hands on the hardware; the host
#        cannot produce it, and unlike the e-stop it is never part of any
#        normal operating state. A broken/absent jumper fails to ARMED — the
#        safe direction.
#      - The firmware still runs and still emits its fail-safe KILL.
#
# HID and MIDI are disabled in BOTH modes: the button is a serial device,
# never a keyboard or instrument the host could be confused into trusting.
import board
import digitalio
import storage
import usb_cdc
import usb_hid
import usb_midi

# Maintenance jumper: GP14 with internal pull-up. Open (no jumper) = HIGH =
# armed; jumpered to GND = LOW = maintenance. GP15 (the e-stop) is left
# untouched here on purpose — see the header.
_jumper = digitalio.DigitalInOut(board.GP14)
_jumper.direction = digitalio.Direction.INPUT
_jumper.pull = digitalio.Pull.UP
_maintenance = not _jumper.value  # LOW (grounded) -> maintenance
_jumper.deinit()

usb_hid.disable()
usb_midi.disable()

if _maintenance:
    usb_cdc.enable(console=True, data=True)
else:
    usb_cdc.enable(console=False, data=True)
    storage.disable_usb_drive()
