#pragma once

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace fss {

enum class ProtectionPolicy {
  PlatformDefault,
  HardwareBackedPreferred,
  HardwareBackedRequired,
  SoftwareProtected,
};

struct ProviderCapabilities {
  std::string name;
  bool hardware_available = false;
  bool storage_protection_hardware_backed = false;
  bool private_key_hardware_backed = false;
  bool same_user_compromise_resistant = false;
  bool root_compromise_resistant = false;
  std::string fallback_reason;
};

class LinuxStorageProvider {
public:
  virtual ~LinuxStorageProvider() = default;
  virtual std::string name() const = 0;
  virtual bool available() const = 0;
  virtual ProviderCapabilities capabilities() const = 0;

  virtual void write(const std::string &account, const std::string &key,
                     const std::string &value) = 0;
  virtual std::optional<std::string> read(const std::string &account,
                                          const std::string &key) = 0;
  virtual void remove(const std::string &account, const std::string &key) = 0;
  virtual void removeAll(const std::string &account) = 0;
  virtual std::map<std::string, std::string>
  readAll(const std::string &account) = 0;
  virtual bool contains(const std::string &account,
                        const std::string &key) = 0;
};

std::unique_ptr<LinuxStorageProvider>
selectProvider(ProtectionPolicy policy, bool headless,
               bool allow_filesystem_only_master_key);

} // namespace fss
