# Production promotion plan (`main`)

## Branch roles

| Branch | Role |
|--------|------|
| `develop` | Ongoing integration (unchanged; never rewritten) |
| `feature/desktop-hardware-backed-storage` | Implementation branch |
| `main` | Production / release branch |

Do **not** create `master` if `main` is used. Do not delete `develop`.

## Steps

1. Open PR: `feature/desktop-hardware-backed-storage` → `develop`.
2. Require green CI (`CI` + `Desktop Smoke`).
3. Merge into `develop` when approved (no auto-merge unless policy allows).
4. Create / update `main` from the tested release commit on `develop`.
5. Open PR: `develop` → `main` for formal promotion (or fast-forward `main` to the release commit after approval).
6. After approval and green checks on `main`, create **immutable** tag:
   ```bash
   git tag -a desktop-secure-storage-v11.0.0 <main-commit-sha> -m "Desktop secure storage 11.0.0"
   git push origin desktop-secure-storage-v11.0.0
   ```
7. Optional fl-start pin tag: `v11.0.0-fl.1` pointing at the same commit.
8. Never move or overwrite `desktop-secure-storage-v11.0.0`.
