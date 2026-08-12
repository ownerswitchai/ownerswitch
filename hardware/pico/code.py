# code.py — OwnerSwitch physical kill button (Raspberry Pi Pico, CircuitPython)
#
# WIRING (single-channel, the minimum): the emergency-stop's normally-closed
# (NC) contact sits between GP15 and GND.
#   rest (NC closed)       -> GP15 LOW   -> quiet
#   pressed (NC opens)     -> GP15 HIGH  -> "KILL"
#   cable cut / unplugged  -> GP15 HIGH  -> "KILL"   (fail-safe)
#
# WIRING (dual-channel, optional — issue #40): most mushroom e-stops also
# carry a normally-open (NO) contact. Wire it between GP16 and GND and fit
# the DUAL jumper GP17 -> GND (read ONCE at boot, like the GP14 maintenance
# jumper: a physical act the host cannot fake; no jumper = single-channel,
# which never false-faults). With both channels wired, health is the two
# debounced levels being OPPOSITE:
#   rest    -> NC LOW,  NO HIGH
#   pressed -> NC HIGH, NO LOW
# The levels AGREEING (after a cross-check debounce longer than the contact's
# break-before-make transition) is a hardware fault — both HIGH: a broken
# wire; both LOW: a welded/shorted contact — and raises "FAULT", re-asserted
# while it persists. FAULT is detection only: KILL is raised by the existing
# NC rule and nothing else, and nothing about the NO channel can suppress it.
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

# DUAL jumper (GP17 -> GND): LOW = fitted = dual-channel monitoring armed.
# Read once at boot; an absent or broken jumper fails to single-channel —
# the direction that can never invent a false FAULT.
_dual_jumper = digitalio.DigitalInOut(board.GP17)
_dual_jumper.direction = digitalio.Direction.INPUT
_dual_jumper.pull = digitalio.Pull.UP
time.sleep(0.01)  # let the pull settle before the one decisive read
DUAL = not _dual_jumper.value

no_pin = None
if DUAL:
    no_pin = digitalio.DigitalInOut(board.GP16)
    no_pin.direction = digitalio.Direction.INPUT
    no_pin.pull = digitalio.Pull.UP  # rest = HIGH (NO open); pressed = LOW

DEBOUNCE_S = 0.03
REASSERT_S = 1.0
# Cross-check debounce: must exceed the e-stop's break-before-make transition
# (NC opens before NO closes), so a normal press is never a transient FAULT.
FAULT_DEBOUNCE_S = 0.5
FAULT_REASSERT_S = 5.0
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


enqueue("READY-DUAL" if DUAL else "READY")

prev = pin.value
stable = prev
t_change = time.monotonic()
last_kill = 0.0
# fail-safe: booted into the pressed / wire-broken state -> kill now
if stable:
    enqueue("KILL")
    last_kill = time.monotonic()

# NO-channel debounce state (dual mode only)
no_prev = no_pin.value if no_pin is not None else None
no_stable = no_prev
no_t_change = time.monotonic()
# cross-check state: when the two debounced levels started agreeing, if ever
agree_since = None
faulted = False
last_fault = 0.0

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

    if no_pin is not None:
        nv = no_pin.value
        if nv != no_prev:
            no_prev = nv
            no_t_change = now
        elif nv != no_stable and (now - no_t_change) > DEBOUNCE_S:
            no_stable = nv
        # healthy = opposite; agreement sustained past the cross-check
        # debounce = hardware fault. Detection only — the KILL rule above
        # neither waits for this nor yields to it.
        if stable == no_stable:
            if agree_since is None:
                agree_since = now
            if not faulted and (now - agree_since) > FAULT_DEBOUNCE_S:
                faulted = True
                enqueue("FAULT")
                last_fault = now
        else:
            agree_since = None
            faulted = False
        if faulted and (now - last_fault) > FAULT_REASSERT_S:
            enqueue("FAULT")
            last_fault = now

    drain()
    time.sleep(0.005)
