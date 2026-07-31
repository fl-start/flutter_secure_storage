## 4.2.0

- TPM2-resident private keys via optional `tpm2-tools` (`hardwareBackedRequired` / preferred when available).
- Optional `systemd-creds` DEK wrap provider.
- Standards PKCS#8 PBES2 (AES-256-CBC) export/import and PKCS#10 CSR via shared `DesktopCrypto`.
- Real ECDSA/RSA signatures for software keys.
- Depends on `flutter_secure_storage_platform_interface` ^2.2.0.

## 4.1.0

- Added Linux desktop private-key manager (`LinuxDesktopKeyManager`) with FSS1 records, FSS-EPK1 export, and FSS-CSR1 CSR generation (Windows parity).
- Soft-loads `libsecret` via `dlopen` (no hard link); builds succeed without `libsecret-1-dev`.
- Key-value and DEK wrap fall back to protected-file (`XDG_DATA_HOME`, mode `0700`/`0600`) for headless / minimal distros.
- Honest capability reporting with Secret Service / TPM2 ESAPI runtime probes; `hardwareBackedRequired` fails closed (TPM private-key path not yet implemented).
- Registers `dartPluginClass: FlutterSecureStorageLinux`.

## 4.0.0

- Per-key Secret Service items with legacy JSON migration; protected-file scaffolding + capability channel; TPM2/systemd remain optional runtime providers.

## 3.0.1

- Added support for the `accountName` option to isolate secrets into separate libsecret keyring entries (namespaces).
- Fixed a use-after-free: libsecret error messages are now copied before being thrown (previously the thrown pointer was freed during stack unwinding).
- `warmupKeyring` now runs once per process instead of on every read/contains/delete, avoiding redundant keyring writes and prompts.
- Hardened `SecretStorage` against dangling schema pointers (`setLabel` rebuilds the schema; copy/move disabled).

## 3.0.0

- Fixed whitespace deprecation warning.
- Reverted json.dump with indentations due to problems. If still needed, pin version to 2.x

## 2.0.1

- Fix readAll and deleteAll.

## 2.0.0

- Improved error handling.

## 1.2.0

- Removed libjsoncpp dependency (vendored nlohmann/json).

## 1.1.3

- Fix memory leak.

## 1.1.2

- Fix missing key return value.

## 1.1.1

- Fix for Flutter 3.

## 1.1.0

- Add containsKey.

## 1.0.0

- Initial Linux implementation.
