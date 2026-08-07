# Pre-built feature branches → PRs

This repo ships with three ready-made branches. After the first push, open
them as PRs and review/merge one by one — owner order: kill-state first.

```bash
git push -u origin main
git push origin feat/kill-state feat/veto-window feat/2go-restore

gh pr create --base main --head feat/kill-state  --title "feat(control-plane): kill switch state + audit log"
gh pr create --base main --head feat/veto-window --title "feat(control-plane): veto window state machine"
gh pr create --base main --head feat/2go-restore --title "feat(control-plane): 2GO restore ceremony"
```

Notes:
- Branch commits are scaffold-authored and unsigned; your signed commits
  start with the merge commits on protected main.
- After merging all three, wire exports in `packages/control-plane/src/index.ts`
  and connect `KillSwitch.restore()` to the ceremony's `RestoreAuthorization`.
