#pragma once

#include "linux_storage_provider.hpp"
#include "protected_file_provider.hpp"

namespace fss {

/// Runtime provider selection. TPM / systemd are optional and probed at runtime.
/// This header keeps the base plugin buildable without TPM development headers.
inline std::unique_ptr<LinuxStorageProvider>
selectProvider(ProtectionPolicy policy, bool headless,
               bool allow_filesystem_only_master_key) {
  // Secret Service is preferred for interactive desktop platformDefault.
  // Protected file is the portable fallback for headless / missing keyring.
  if (policy == ProtectionPolicy::HardwareBackedRequired) {
    // TPM provider is dynamically loaded in a follow-on translation unit when
    // libtss2 is present. Without it, fail closed.
    return nullptr;
  }

  if (headless || policy == ProtectionPolicy::SoftwareProtected) {
    return std::make_unique<ProtectedFileProvider>(
        allow_filesystem_only_master_key);
  }

  // Default / preferred: Secret Service remains the primary path implemented
  // via SecretStorage in the plugin. Protected file is available as fallback
  // when libsecret operations fail at runtime.
  return std::make_unique<ProtectedFileProvider>(
      allow_filesystem_only_master_key);
}

} // namespace fss
