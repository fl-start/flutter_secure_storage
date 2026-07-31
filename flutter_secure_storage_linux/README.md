# flutter_secure_storage_linux

Linux implementation of `flutter_secure_storage`.

## Features

- Key-value storage via **Secret Service** (`libsecret`) when available, with **protected-file** fallback for headless / minimal environments
- Desktop private-key API (`DesktopPrivateKeyManager`) with FSS1 records, encrypted export, and CSR generation
- Soft-loads `libsecret` at runtime (`dlopen`) — **not** a hard link dependency
- Optional TPM2 ESAPI probe (`libtss2-esys`) for capability reporting only

## Distro compatibility

| Tier | Runtime needs | Typical environments |
|------|---------------|----------------------|
| Minimal | libc + writable `$HOME` / `XDG_DATA_HOME` | containers, servers, headless |
| Desktop | optional `libsecret-1` + a Secret Service (GNOME Keyring, KWallet, KeePassXC, …) | Ubuntu, Fedora, Arch, openSUSE desktops |
| Hardware probe | optional `libtss2-esys` | TPM hosts (probe only; no build-time TPM headers) |

### Build dependencies

Flutter Linux toolchain (`cmake`, `ninja`, `clang`/`g++`, `pkg-config`, `libgtk-3-dev`).  
**`libsecret-1-dev` is optional** — the plugin builds without it.

### Runtime (desktop keyring)

- `libsecret-1-0` (or distro equivalent) when using Secret Service
- A running Secret Service / keyring agent for interactive unlock

### Runtime (headless)

No keyring required. Data is stored under:

`$XDG_DATA_HOME/<APPLICATION_ID>/secure-storage` (or `~/.local/share/...`)

with directory mode `0700` and file mode `0600`.

## Usage

Prefer the main [`flutter_secure_storage`](../flutter_secure_storage) package. See [DESKTOP_STORAGE.md](../DESKTOP_STORAGE.md) for the private-key API.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
