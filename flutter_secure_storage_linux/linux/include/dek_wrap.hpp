#pragma once

#include <cstdint>
#include <string>
#include <vector>

#ifndef APPLICATION_ID
#define APPLICATION_ID "flutter_secure_storage"
#endif

enum class DekWrapProvider {
  SecretService,
  ProtectedFile,
};

struct DekWrapResult {
  bool ok = false;
  std::string error_code;
  std::string error_message;
  std::vector<uint8_t> token;
  std::string provider;
};

/// Prefer Secret Service when available and not headless; else protected-file.
DekWrapProvider select_dek_provider(bool force_protected_file);

DekWrapResult wrap_dek(const std::string &key_id,
                       const std::vector<uint8_t> &dek,
                       bool force_protected_file);

DekWrapResult unwrap_dek(const std::vector<uint8_t> &token);

DekWrapResult delete_wrapped_dek(const std::vector<uint8_t> &token);
