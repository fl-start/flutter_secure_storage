#pragma once

#include "linux_storage_provider.hpp"
#include "protected_file_provider.hpp"
#include "../secret_service_loader.hpp"
#include "../tpm_probe.hpp"

namespace fss {

/// Runtime provider selection. TPM / systemd are optional and probed at runtime.
inline std::unique_ptr<LinuxStorageProvider>
selectProvider(ProtectionPolicy policy, bool headless,
               bool allow_filesystem_only_master_key) {
  if (policy == ProtectionPolicy::HardwareBackedRequired) {
    // TPM-resident KV not implemented; fail closed.
    if (!fss_probe_tpm2_available()) {
      return nullptr;
    }
    return nullptr;
  }

  if (headless || policy == ProtectionPolicy::SoftwareProtected ||
      !SecretServiceLoader::instance().available() ||
      !SecretServiceLoader::sessionBusPresent()) {
    return std::make_unique<ProtectedFileProvider>(
        allow_filesystem_only_master_key);
  }

  // Secret Service preferred for interactive desktop; callers may still fall
  // back to ProtectedFileProvider if libsecret operations fail.
  return std::make_unique<ProtectedFileProvider>(
      allow_filesystem_only_master_key);
}

inline bool prefer_secret_service_kv(bool headless) {
  return !headless && SecretServiceLoader::instance().available() &&
         SecretServiceLoader::sessionBusPresent();
}

} // namespace fss
