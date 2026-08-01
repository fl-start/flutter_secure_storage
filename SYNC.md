# Branch policy (fl-start fork)

## Production branch

**`main` is the only production branch.** All releases, tags, documentation, and consumer pins ship from `main`.

## `develop` is frozen forever

The `develop` branch **exists permanently** as a historical / upstream-tracking artifact and **MUST NEVER be synced with `main`**.

- Do **not** merge `develop` → `main`
- Do **not** merge `main` → `develop`
- Do **not** rebase either branch onto the other
- Do **not** treat `develop` as a release candidate or SecMail pin target

If work appears only on `develop`, re-implement or cherry-pick intentionally onto `main` as a new change. Never “catch up” the two histories.

## Upstream

This fork originally tracked [juliansteenbakker/flutter_secure_storage](https://github.com/juliansteenbakker/flutter_secure_storage). fl-start production **does not** continuously merge upstream `develop` into `main`. Selective ports of upstream fixes may be applied as ordinary PRs to `main` when needed.

## Releases (from `main` only)

1. Bump package versions and changelogs on `main`.
2. Run CI (`melos analyze`, tests, platform jobs).
3. Tag:
   - `desktop-secure-storage-vX.Y.Z` (product / desktop+mobile secure-storage pin)
   - `vX.Y.Z-fl.1` (fl-start pin alias)
4. Create a GitHub Release for the tag when publishing notes.
5. Consumers pin via Git until/unless published to pub.dev:

```yaml
dependencies:
  flutter_secure_storage:
    git:
      url: https://github.com/fl-start/flutter_secure_storage.git
      ref: desktop-secure-storage-v11.0.4
      path: flutter_secure_storage
```

## Web

**Web is not supported** by this fork’s product guarantees. See [openspec/specs/kv-storage/spec.md](openspec/specs/kv-storage/spec.md) and [README_FL_START.md](README_FL_START.md).
