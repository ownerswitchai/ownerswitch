# First 15 minutes (local)

```bash
# 0. prerequisites: node 22+, pnpm 9 (corepack enable), gh CLI logged in
cd ownerswitch
pnpm install          # generates pnpm-lock.yaml — commit it!
pnpm typecheck && pnpm test   # should be green

# 1. git + signed commits (SSH signing, one-time setup)
git init -b main
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519.pub
git config commit.gpgsign true
git add .
git commit -m "chore: initial scaffold — policy engine, landing, CI"

# 2. push to the org
gh repo create ownerswitchai/ownerswitch --private --source=. --push

# 3. branch protection (web): repo Settings → Branches → protect main,
#    require PR + require status checks: "verify"

# 4. Vercel: Add New Project → import ownerswitchai/ownerswitch
#    Root Directory: apps/web   (Framework: Other / static)

# 5. Porkbun DNS (Domain Management → ownerswitch.ai → DNS):
#    A     @    76.76.21.21
#    CNAME www  cname.vercel-dns.com
#    ...then add ownerswitch.ai as Domain in the Vercel project.
```
