#pragma once

#include "linux_storage_provider.hpp"
#include <cctype>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <sstream>

#ifndef APPLICATION_ID
#define APPLICATION_ID "flutter_secure_storage"
#endif

namespace fss {

/// Encrypted-file backend for headless / non-GNOME environments.
///
/// Requires explicit allow_filesystem_only_master_key for raw 0600 key file.
/// Directory mode 0700, file mode 0600, rejects symlink paths.
class ProtectedFileProvider : public LinuxStorageProvider {
public:
  explicit ProtectedFileProvider(bool allow_filesystem_only_master_key)
      : allow_fs_key_(allow_filesystem_only_master_key) {}

  std::string name() const override { return "linux_protected_file"; }

  bool available() const override {
    try {
      auto root = rootDir();
      std::error_code ec;
      std::filesystem::create_directories(root, ec);
      return !ec;
    } catch (...) {
      return false;
    }
  }

  ProviderCapabilities capabilities() const override {
    ProviderCapabilities caps;
    caps.name = name();
    caps.hardware_available = false;
    caps.storage_protection_hardware_backed = false;
    caps.private_key_hardware_backed = false;
    caps.same_user_compromise_resistant = false;
    caps.root_compromise_resistant = false;
    if (!allow_fs_key_) {
      caps.fallback_reason =
          "filesystem-only master key disabled; set allowFilesystemOnlyMasterKey";
    }
    return caps;
  }

  void write(const std::string &account, const std::string &key,
             const std::string &value) override {
    ensureReady();
    auto path = recordPath(account, key);
    atomicWrite(path, value);
  }

  std::optional<std::string> read(const std::string &account,
                                  const std::string &key) override {
    ensureReady();
    auto path = recordPath(account, key);
    if (!std::filesystem::exists(path) || std::filesystem::is_symlink(path)) {
      return std::nullopt;
    }
    std::ifstream in(path, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
  }

  void remove(const std::string &account, const std::string &key) override {
    auto path = recordPath(account, key);
    std::error_code ec;
    std::filesystem::remove(path, ec);
  }

  void removeAll(const std::string &account) override {
    auto dir = accountDir(account);
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
  }

  std::map<std::string, std::string>
  readAll(const std::string &account) override {
    std::map<std::string, std::string> out;
    auto dir = accountDir(account);
    if (!std::filesystem::exists(dir)) {
      return out;
    }
    for (auto &entry : std::filesystem::directory_iterator(dir)) {
      if (!entry.is_regular_file()) {
        continue;
      }
      auto name = entry.path().filename().string();
      if (name.size() < 5 || name.substr(name.size() - 5) != ".fss1") {
        continue;
      }
      std::ifstream in(entry.path(), std::ios::binary);
      std::ostringstream ss;
      ss << in.rdbuf();
      out[name] = ss.str();
    }
    return out;
  }

  bool contains(const std::string &account, const std::string &key) override {
    return read(account, key).has_value();
  }

private:
  bool allow_fs_key_;

  void ensureReady() const {
    if (!allow_fs_key_) {
      throw std::runtime_error("unsafeFilesystemPermissions: filesystem master key not allowed");
    }
    auto root = rootDir();
    std::filesystem::create_directories(root);
    chmod(root.c_str(), 0700);
    if (std::filesystem::is_symlink(root)) {
      throw std::runtime_error("unsafeFilesystemPermissions: symlink root rejected");
    }
  }

  static std::filesystem::path rootDir() {
    const char *xdg = getenv("XDG_DATA_HOME");
    std::filesystem::path base;
    if (xdg && *xdg) {
      base = xdg;
    } else {
      const char *home = getenv("HOME");
      if (!home) {
        throw std::runtime_error("HOME unset");
      }
      base = std::filesystem::path(home) / ".local" / "share";
    }
    return base / APPLICATION_ID / "secure-storage";
  }

  std::filesystem::path accountDir(const std::string &account) const {
    return rootDir() / sanitize(account);
  }

  std::filesystem::path recordPath(const std::string &account,
                                   const std::string &key) const {
    return accountDir(account) / (sanitize(key) + ".fss1");
  }

  static std::string sanitize(const std::string &in) {
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
      if (std::isalnum((unsigned char)c) || c == '.' || c == '-' || c == '_') {
        out.push_back(c);
      } else {
        out.push_back('_');
      }
    }
    if (out.empty()) {
      out = "key";
    }
    return out;
  }

  static void atomicWrite(const std::filesystem::path &path,
                          const std::string &payload) {
    std::filesystem::create_directories(path.parent_path());
    if (std::filesystem::is_symlink(path.parent_path()) ||
        std::filesystem::is_symlink(path)) {
      throw std::runtime_error("unsafeFilesystemPermissions: symlink rejected");
    }
    auto tmp = path;
    tmp += ".tmp";
    {
      std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
      out.write(payload.data(), (std::streamsize)payload.size());
      out.flush();
      out.close();
      int fd = ::open(tmp.c_str(), O_RDONLY);
      if (fd >= 0) {
        ::fsync(fd);
        ::close(fd);
      }
    }
    chmod(tmp.c_str(), 0600);
    std::filesystem::rename(tmp, path);
    // fsync parent directory
    int dirfd = ::open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY);
    if (dirfd >= 0) {
      ::fsync(dirfd);
      ::close(dirfd);
    }
  }
};

} // namespace fss
