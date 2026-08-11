# boot.py — OwnerSwitch kill button (Raspberry Pi Pico, CircuitPython)
#
# Expose a DEDICATED USB serial "data" channel, separate from the REPL console,
# so the KILL signal is clean (no REPL noise). The OwnerSwitch button daemon
# reads this data port. Runs once at power-on / reset.
import usb_cdc

usb_cdc.enable(console=True, data=True)
