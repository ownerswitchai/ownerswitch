# Quickstart

Fresh machine to a working, enforcing gateway. Node 22+ and pnpm 9
(`corepack enable`) are the only prerequisites.

```bash
git clone https://github.com/ownerswitchai/ownerswitch && cd ownerswitch
pnpm install                  # installs AND builds the workspace (~15s build)
pnpm typecheck && pnpm test   # optional, ~1 min: everything should be green
```

`pnpm install` runs the root `prepare` script, which builds every package —
the packages import each other's build output, so an installed-but-unbuilt
tree fails with `ERR_MODULE_NOT_FOUND … /dist/index.js` on the first command
you run. If you ever see that, `pnpm build` is the fix. The
`WARN Failed to create bin … ENOENT` lines during that first install are the
same ordering, and they disappear on the next one.

Then, in two terminals:

```bash
# terminal 1 — the control plane holds kill state; leave it running
pnpm --filter @ownerswitchai/mcp dev:control-plane

# terminal 2 — preflight, then the in-repo demo agent behind the gateway
cd packages/mcp
npx tsx src/cli.ts doctor --config examples/first-kill.config.json
npx tsx examples/first-kill-agent.ts
```

**→ [FIRST-KILL.md](FIRST-KILL.md) walks the whole path in about 10
minutes** and ends with you stopping that agent and bringing it back through
the two-GO ceremony. No AI client and no API key: the demo agent and its
tool server live in this repo, so nothing downloads.

Reference documentation for every configuration field, error code and lane:
[`packages/mcp/README.md`](packages/mcp/README.md). What the gateway does and
does not contain: [`packages/mcp/THREAT-MODEL.md`](packages/mcp/THREAT-MODEL.md).

---

## Maintainer bootstrap

Only for standing up a *new* deployment of this repo — not needed to run or
develop OwnerSwitch.

```bash
# git + signed commits (SSH signing, one-time setup)
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519.pub
git config commit.gpgsign true

# branch protection (web): repo Settings → Branches → protect main,
#   require PR + require status checks: "verify"

# Vercel: Add New Project → import the repo
#   Root Directory: apps/web   (Framework: Other / static)

# DNS (Porkbun → Domain Management → ownerswitch.ai → DNS):
#   A     @    76.76.21.21
#   CNAME www  cname.vercel-dns.com
#   ...then add ownerswitch.ai as Domain in the Vercel project.
```
