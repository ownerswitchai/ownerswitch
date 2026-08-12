# code.py — OwnerSwitch physical kill button (Raspberry Pi Pico, CircuitPython)
#
# WIRING: the emergency-stop's normally-closed (NC) contact sits between GP15
# and GND.
#   rest (NC closed)       -> GP15 LOW   -> quiet
#   pressed (NC opens)     -> GP15 HIGH  -> "KILL"
#   cable cut / unplugged  -> GP15 HIGH  -> "KILL"   (fail-safe)
#
# Emits over the dedicated USB data channel only (boot.py). Every write is
# NON-BLOCKING: the monitoring loop must never stall behind a slow or absent
# reader — a stalled loop would defeat the boot-time fail-safe and miss
# presses. Undelivered bytes wait in a small outbox and are re-offered each
# tick; while GP15 is HIGH the firmware re-asserts "KILL" every second, so a
# dropped or partially delivered line is always followed by a complete one
# (the host daemon de-dupes and POST /kill is idempotent).
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
# Small: framing never depends on it — if it is full, the 1 s re-assert
# re-offers the same line soon anyway.
OUTBOX_CAP = 64

data = usb_cdc.data
if data is not None:
    # Non-blocking writes: return immediately with the byte count accepted
    # (possibly 0) instead of waiting for the host to drain the buffer.
    data.write_timeout = 0

outbox = bytearray()


def enqueue(line):
    # Whole lines only. Never drop the head of the outbox — it may be the
    # partially sent front of a line, and framing must survive.
    if len(outbox) < OUTBOX_CAP:
        outbox.extend(line.encode("utf-8") + b"\n")


def drain():
    # Hand the host whatever it will take right now; keep the rest.
    if data is None or not outbox:
        return
    if not data.connected:
        return  # nobody listening; the re-assert keeps the outbox fresh
    try:
        written = data.write(outbox) or 0
    except Exception:
        return
    if written:
        del outbox[:written]


enqueue("READY")

prev = pin.value
stable = prev
t_change = time.monotonic()
last_kill = 0.0
# fail-safe: booted into the pressed / wire-broken state -> kill now
if stable:
    enqueue("KILL")
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
            enqueue("KILL")
            last_kill = now
    # keep re-asserting while HIGH (idempotent on the daemon)
    if stable and (now - last_kill) > REASSERT_S:
        enqueue("KILL")
        last_kill = now
    drain()
    time.sleep(0.005)
