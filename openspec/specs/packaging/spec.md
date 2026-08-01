# Spec: Packaging and versioning

## Purpose

Define how fl-start packages are consumed, versioned, and declared for platforms.

## Primary distribution: GitHub git dependency

fl-start’s **primary** supported consumption path is a **git dependency** on this repository.

### Required shape

```yaml
dependencies:
  flutter_secure_storage:
    git:
      url: https://github.com/fl-start/flutter_secure_storage.git
      ref: desktop-secure-storage-vX.Y.Z   # e.g. desktop-secure-storage-v11.0.4
      path: flutter_secure_storage
```

Requirements:

1. Consumers SHOULD pin an immutable `desktop-secure-storage-v*` tag (or `v*-fl.*` pin).
2. `path` MUST be `flutter_secure_storage` for the app-facing package.
3. When Melos/`dependency_overrides` are not used, consumers MAY need overrides for federated packages (`flutter_secure_storage_platform_interface`, `_darwin`, `_linux`, `_windows`, and optionally `_web` for resolution only).
4. Documentation for SecMail and other fl-start apps SHALL prefer git refs over unpublished path hacks in CI.

### Local path (dev only)

Path dependencies MAY be used in monorepo / local workspaces; they are not the production pin mechanism.

## pub.dev readiness

Even though git is primary:

1. Package `pubspec.yaml` files SHALL remain **pub.dev-ready** (valid metadata, SDK constraints, federated plugin layout).
2. Versions SHALL follow semver appropriate to public API changes (private-key surface was a major bump to **11.x**).
3. `repository:` URLs SHOULD point at `fl-start/flutter_secure_storage`.
4. Publishing to pub.dev is optional and not required for fl-start production consumption; git tags remain authoritative for fl-start apps.

## Federated packages

| Package | Notes |
|---------|-------|
| `flutter_secure_storage` | Facade; version is the consumer-facing train (e.g. 11.0.4) |
| `flutter_secure_storage_platform_interface` | Shared types / FSS1 / channel |
| `flutter_secure_storage_darwin` | iOS + macOS |
| `flutter_secure_storage_linux` | Linux |
| `flutter_secure_storage_windows` | Windows |
| `flutter_secure_storage_web` | Retained in monorepo historically; **not wired** into the main plugin; unsupported |

Version bumps across packages SHOULD stay coherent for a given release tag (document mismatches in the release notes if unavoidable).

## Platforms declaration

### Product policy vs pubspec mechanics

- **Product policy:** fl-start supports Android, iOS, Windows, macOS, Linux. **Web is unsupported.**
- Pubspecs MAY still list `web:` under `flutter.plugin.platforms` / `platforms:` so that `pub` federation and analyzer resolution do not break for apps that accidentally resolve the web package.
- Such listing **MUST NOT** be documented as “fl-start supports Web.”
- README / OpenSpec / release notes SHALL state there is **no Web support guarantee**.

### Recommended consumer stance

- Mobile + desktop native targets: supported.
- Web / Wasm browser targets: out of scope; do not depend on fl-start for secret storage on Web.

## Versioning and tags

| Artifact | Meaning |
|----------|---------|
| Package `version:` in pubspecs | Semver for the federated packages |
| `desktop-secure-storage-vX.Y.Z` | Immutable production git tag on `main` |
| `vX.Y.Z-fl.N` | Optional fl-start pin tag |

Rules:

1. A release that changes user-visible secure storage / private-key guarantees SHOULD bump the appropriate semver component.
2. Tag `X.Y.Z` SHOULD match the facade package version for that release when practical.
3. See [branching](../branching/spec.md) for immutability and no-`develop`-sync rules.

## Melos / workspace

- Root `melos.yaml` MAY orchestrate bootstrap/analyze/test.
- CI SHOULD analyze the federated packages used in production.
- Example apps MAY use `pubspec_overrides.yaml`; overrides MUST NOT be required by end-app git pins beyond documented federated overrides.

## Non-goals

- Guaranteeing pub.dev publish cadence.
- Supporting Web as a first-class fl-start platform via packaging tricks.
- Requiring consumers to track `develop`.
