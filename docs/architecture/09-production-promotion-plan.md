# Production promotion plan (`main`)

## Branch roles

| Branch | Role |
|--------|------|
| `main` | **Only** production / release branch |
| `develop` | Frozen forever; **MUST NEVER** be synced with `main` (see `SYNC.md`) |

Do **not** merge `develop` ↔ `main` in either direction. Do not delete `develop`.

## Steps

1. Land changes on `main` via PR (or direct push when intentional).
2. Require green CI on `main`.
3. Bump versions + changelogs.
4. Create **immutable** tags on the release commit:
   ```bash
   git tag -a desktop-secure-storage-v11.0.4 <main-commit-sha> -m "Secure storage 11.0.4"
   git tag -a v11.0.4-fl.1 <main-commit-sha> -m "fl-start pin 11.0.4"
   git push origin desktop-secure-storage-v11.0.4 v11.0.4-fl.1
   ```
5. Publish a GitHub Release for the product tag.
6. Consumers pin the Git tag until/unless pub.dev publish is performed.
7. Never move or overwrite an existing `desktop-secure-storage-vX.Y.Z` tag.
