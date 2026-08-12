# boot.py — OwnerSwitch kill button (Raspberry Pi Pico, CircuitPython)
#
# Two jobs, both about the trust boundary between the button and the host it
# is meant to stop. Runs once at power-on / reset, before USB enumerates.
#
# 1. Expose a DEDICATED USB serial "data" channel for the KILL signal.
# 2. Decide the mode by a PHYSICAL gesture the host cannot fake:
#
#    ARMED (normal): e-stop at rest (GP15 LOW) when power arrives.
#      - CIRCUITPY mass storage DISABLED: the host this button plugs into is
#        exactly the machine the agent runs on — a writable firmware volume
#        would let a compromised host rewrite code.py and make the next
#        physical press silent.
#      - REPL console DISABLED: a console lets the host Ctrl-C the firmware
#        into the REPL, stopping the monitoring loop — same failure class.
#      - Exactly one serial device appears: the data channel.
#
#    MAINTENANCE: e-stop LATCHED PRESSED (GP15 HIGH) when power arrives —
#    twist-latch the button, then plug in USB.
#      - CIRCUITPY drive and REPL console stay enabled for editing/debugging.
#      - Only hands on the hardware can produce this state; the firmware
#        still emits its fail-safe KILL while latched.
#
# HID and MIDI are disabled in BOTH modes: the button is a serial device,
# never a keyboard or instrument the host could be confused into trusting.
import board
import digitalio
import storage
import usb_cdc
import usb_hid
import usb_midi

# Maintenance gate: NC contact between GP15 and GND, internal pull-up.
# Rest = LOW; latched-pressed (or open wire) = HIGH.
_pin = digitalio.DigitalInOut(board.GP15)
_pin.direction = digitalio.Direction.INPUT
_pin.pull = digitalio.Pull.UP
_maintenance = _pin.value  # HIGH -> maintenance
_pin.deinit()  # release GP15 for code.py

usb_hid.disable()
usb_midi.disable()

if _maintenance:
    usb_cdc.enable(console=True, data=True)
else:
    usb_cdc.enable(console=False, data=True)
    storage.disable_usb_drive()
