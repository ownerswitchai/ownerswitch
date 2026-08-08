# Contributing

## Security conventions

This repo has learned the rules below the hard way — each one closes a class
of mistake an external review actually found here. If you're touching
anything security-relevant, follow them; if you're adding a new one, add it
to this list.

- **Secrets never come from argv.** A flag like `--owner-token` is readable
  in shell history and in `ps` output from any other user on the box.
  Accept secrets from an environment variable, an interactive no-echo stdin
  prompt, or an owner-only file — never a CLI argument. Found and fixed
  twice: `--owner-token` (#19) and `--canary-key` (#15). See
  `resolveOwnerToken` in `packages/mcp/src/verify.ts`.

- **Fail closed on doubt.** An answer that's unparseable, missing, or timed
  out is a "no," not a "yes" — treat it as killed/denied, never as
  permitted. Guessing in the permissive direction is how a network blip
  becomes a bypass. See `packages/gateway/src/client.ts`.

- **No silent defaults for security-relevant values.** If a value can't be
  read, don't substitute a default and carry on — fail instead. The
  canonical case: `epoch` must never default to `0` on a missing/invalid
  response, because that would make every ticket minted before a
  deployment's first kill look permanently current. See the epoch handling
  in `packages/gateway/src/client.ts`.

- **Every outbound request gets a bounded timeout.** Nothing waits forever
  on a remote call — an unbounded wait is an availability bug and, for
  anything gating a security decision, a silent fail-open. See the
  `AbortController` timeout in `packages/gateway/src/client.ts`.

- **Files holding security state get hardened I/O**, not `fs.readFile` /
  `fs.writeFile` defaults: refuse to follow symlinks, cap size before
  parsing, write at mode `0600`, and publish via atomic temp-file-then-rename
  so a reader never sees a torn write. See `packages/control-plane/src/kill-state.ts`.

- **Don't overclaim in docs or copy.** The threat model is the source of
  truth for what this system actually defends against; a narrow claim you
  can defend beats a broad one you can't. If a doc and the code disagree,
  the code wins and the doc needs fixing.

When in doubt, match the pattern in the files linked above rather than
inventing a new one.
