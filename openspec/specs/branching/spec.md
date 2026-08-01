# Spec: Branching and release train

## Purpose

Define how fl-start manages git branches, upstream relationship, and release tags for production `flutter_secure_storage`.

## Branch roles

| Branch | Role |
|--------|------|
| **`main`** | **Production.** Only branch from which production releases are cut. |
| **`develop`** | Long-lived historical / integration branch. **Exists forever.** |
| Feature branches | Short-lived work; merge target is policy-defined (typically PRs into `main` for production work). |

## Normative rules

### Production

1. **`main` SHALL be the sole production branch.**
2. Production releases MUST be created from commits that are on `main` (or become on `main` before tagging).
3. Immutable production tags MUST point at `main` commits.

### `develop` freeze / no-sync policy

1. The `develop` branch **MUST continue to exist** (do not delete it).
2. fl-start **MUST NEVER sync `develop` with `main`.**
   - MUST NOT merge `main` into `develop` to “catch up.”
   - MUST NOT merge `develop` into `main` as a routine promotion sync.
   - MUST NOT reset / rewrite `develop` to match `main`.
3. Documentation that previously suggested “sync develop with main release history” is **superseded** by this OpenSpec for fl-start production policy.
4. `develop` MAY remain as a frozen or divergent historical line; it is **not** the production source of truth.

### Upstream policy

1. fl-start production **MUST NOT** follow an “always merge `upstream/develop`” policy for shipping `main`.
2. Selective cherry-picks or manual ports of upstream fixes onto `main` MAY be performed when explicitly needed, with review and tests.
3. Agents MUST NOT reopen automated upstream/`develop` merge as the default production workflow without an OpenSpec change approved by maintainers.

### Feature work

1. New production features SHOULD land via PRs targeting **`main`** (or a release branch that merges to `main`), not via resurrecting `develop` as the integration trunk.
2. Existing feature branches MAY be completed into `main` after review.

## Tags

### Primary production tag

Format:

```text
desktop-secure-storage-vX.Y.Z
```

Examples: `desktop-secure-storage-v11.0.0` … `desktop-secure-storage-v11.0.4`.

Rules:

- Tags of this form are **immutable**. MUST NOT move or force-update.
- Annotated tags SHOULD be used.
- Dependents SHOULD pin this tag for CI/releases.

### fl-start pin tag

Format:

```text
vX.Y.Z-fl.N
```

Examples: `v11.0.3-fl.1`, `v11.0.4-fl.1`.

Rules:

- Optional convenience pin; SHOULD point at the **same commit** as the matching `desktop-secure-storage-vX.Y.Z` when published together.
- `N` starts at `1` for a given `X.Y.Z` unless a documented re-pin policy says otherwise; prefer not to re-pin — cut a new patch instead.

### Consumption example

```yaml
dependencies:
  flutter_secure_storage:
    git:
      url: https://github.com/fl-start/flutter_secure_storage.git
      ref: desktop-secure-storage-v11.0.4
      path: flutter_secure_storage
```

## Release checklist (normative process)

1. Land changes on `main` with green CI.
2. Bump federated package versions consistently.
3. Update changelogs / OpenSpec change records as needed.
4. Tag `desktop-secure-storage-vX.Y.Z` on the release commit on `main`.
5. Optionally tag `vX.Y.Z-fl.1` at the same commit.
6. Push tags to `origin`.
7. **Do not** sync `develop` afterward.

## Non-goals

- Using `master` as an alias production branch.
- Treating `origin/HEAD → develop` as production guidance for fl-start consumers.
- Rewriting tag history.
