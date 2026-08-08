# @ownerswitchai/mcp — MCP gateway (in progress)

The MCP-facing surface of OwnerSwitch: agent tool calls route through
here and are decided by the policy engine (`@ownerswitchai/gateway`)
against live kill state — fail-closed on doubt, every decision logged.

## Enforcement boundary

This gateway decides and audits **the calls that route through it** —
only those. An agent that also has built-in tools or direct
file/shell/network access can act without asking, and a denial removes
permission, not capability. We have watched exactly that (2026-08-08):
two correct fail-closed denials, then — after the user repeated the
request — the agent did the write with its own built-in tool, announcing
it as it went. The gateway held; the effect happened anyway.

If you need containment, build the deployment around the gateway for it:
credential broker, sandboxed egress, OS-level enforcement — honestly
ranked in **[THREAT-MODEL.md](./THREAT-MODEL.md)**. The quickstart alone
is policy and audit, not a cage.
