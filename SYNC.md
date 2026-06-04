# Upstream sync policy (fl-start fork)

This repository tracks [juliansteenbakker/flutter_secure_storage](https://github.com/juliansteenbakker/flutter_secure_storage) `develop`, with fl-start–specific changes on top.

## Cadence

- **Weekly check** (or before a SecMail release): fetch `upstream/develop`, review diff, merge if CI is green.
- **Emergency patches**: commit directly on `develop`; tag a fl-start release immediately.

## Remotes

```bash
git remote add upstream https://github.com/juliansteenbakker/flutter_secure_storage.git
git fetch upstream
git merge upstream/develop
```

## fl-start–only changes to preserve on merge

- `LinuxOptions.accountName` and Linux plugin namespaces
- `WindowsOptions.accountName` / `useLocalMachine` and DPAPI file naming
- `DESKTOP_STORAGE.md`, `docs/macos_entitlements.md`, `SYNC.md`, `README_FL_START.md`
- Repository URLs in `pubspec.yaml` pointing to `fl-start/flutter_secure_storage`

## Releases

1. Bump package versions in the monorepo (main + platform packages).
2. Run `melos bootstrap` and `melos analyze`.
3. Tag: `git tag v10.0.1-fl.1` (example).
4. Pin dependents: `ref: v10.0.1-fl.1` or path dependency for local workspace.

## Version scheme

- Upstream semantic version + fl-start patch: **10.0.1** with git tag **`v10.0.1-fl.1`**.
