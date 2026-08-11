# code.py — OwnerSwitch physical kill button (Raspberry Pi Pico, CircuitPython)
#
# WIRING: the emergency-stop's normally-closed (NC) contact sits between GP15
# and GND.
#   rest (NC closed)       -> GP15 LOW   -> quiet
#   pressed (NC opens)     -> GP15 HIGH  -> "KILL"
#   cable cut / unplugged  -> GP15 HIGH  -> "KILL"   (fail-safe)
#
# Emits one line over USB on every press edge. Also fail-safe on boot (if it
# comes up already HIGH) and re-asserts every second while HIGH, so a dropped
# line still lands — the host daemon debounces and POST /kill is idempotent.
#
# Pairs with `ownerswitch-button --source serial` (packages/button).
import board
import digitalio
import time
import usb_cdc

pin = digitalio.DigitalInOut(board.GP15)
pin.direction = digitalio.Direction.INPUT
pin.pull = digitalio.Pull.UP  # rest = LOW (NC closed); pressed/broken = HIGH

DEBOUNCE_S = 0.03
REASSERT_S = 1.0


def emit(line):
    # print() -> console serial (visible in a REPL); usb_cdc.data -> the daemon.
    try:
        print(line)
    except Exception:
        pass
    if usb_cdc.data is not None:
        try:
            usb_cdc.data.write((line + "\n").encode("utf-8"))
        except Exception:
            pass


emit("READY")

prev = pin.value
stable = prev
t_change = time.monotonic()
last_kill = 0.0
# fail-safe: booted into the pressed / wire-broken state -> kill now
if stable:
    emit("KILL")
    last_kill = time.monotonic()

while True:
    v = pin.value
    now = time.monotonic()
    if v != prev:
        prev = v
        t_change = now  # raw change: restart the debounce timer
    elif v != stable and (now - t_change) > DEBOUNCE_S:
        stable = v  # commit a debounced level
        if stable:  # LOW->HIGH: pressed or wire broken
            emit("KILL")
            last_kill = now
    # keep re-asserting while HIGH (idempotent on the daemon)
    if stable and (now - last_kill) > REASSERT_S:
        emit("KILL")
        last_kill = now
    time.sleep(0.005)
