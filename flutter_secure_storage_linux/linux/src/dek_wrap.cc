#include "include/dek_wrap.hpp"
#include "include/FHashTable.hpp"
#include "include/secret_service_loader.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace {

constexpr char kSsPrefix[] = "ss1:";
constexpr char kPfPrefix[] = "pf1:";

std::string sanitize(const std::string &in) {
  std::string out;
  out.reserve(in.size());
  for (char c : in) {
    if (std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' ||
        c == '_') {
      out.push_back(c);
    } else {
      out.push_back('_');
    }
  }
  return out.empty() ? "key" : out;
}

std::filesystem::path dek_root() {
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
  return base / APPLICATION_ID / "private_keys" / "deks";
}

std::string b64_encode(const std::vector<uint8_t> &data) {
  static const char kTable[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((data.size() + 2) / 3) * 4);
  size_t i = 0;
  while (i + 2 < data.size()) {
    uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
    out.push_back(kTable[(n >> 18) & 63]);
    out.push_back(kTable[(n >> 12) & 63]);
    out.push_back(kTable[(n >> 6) & 63]);
    out.push_back(kTable[n & 63]);
    i += 3;
  }
  if (i < data.size()) {
    uint32_t n = data[i] << 16;
    out.push_back(kTable[(n >> 18) & 63]);
    if (i + 1 < data.size()) {
      n |= data[i + 1] << 8;
      out.push_back(kTable[(n >> 12) & 63]);
      out.push_back(kTable[(n >> 6) & 63]);
      out.push_back('=');
    } else {
      out.push_back(kTable[(n >> 12) & 63]);
      out.push_back('=');
      out.push_back('=');
    }
  }
  return out;
}

std::vector<uint8_t> b64_decode(const std::string &in) {
  auto val = [](char c) -> int {
    if (c >= 'A' && c <= 'Z')
      return c - 'A';
    if (c >= 'a' && c <= 'z')
      return c - 'a' + 26;
    if (c >= '0' && c <= '9')
      return c - '0' + 52;
    if (c == '+')
      return 62;
    if (c == '/')
      return 63;
    return -1;
  };
  std::vector<uint8_t> out;
  int valb = -8;
  uint32_t accum = 0;
  for (char c : in) {
    if (c == '=')
      break;
    int d = val(c);
    if (d < 0)
      continue;
    accum = (accum << 6) | static_cast<uint32_t>(d);
    valb += 6;
    if (valb >= 0) {
      out.push_back(static_cast<uint8_t>((accum >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return out;
}

std::vector<uint8_t> make_token(const char *prefix, const std::string &id) {
  std::string s = std::string(prefix) + id;
  return std::vector<uint8_t>(s.begin(), s.end());
}

bool parse_token(const std::vector<uint8_t> &token, std::string &prefix,
                 std::string &id) {
  std::string s(token.begin(), token.end());
  if (s.rfind(kSsPrefix, 0) == 0) {
    prefix = kSsPrefix;
    id = s.substr(std::strlen(kSsPrefix));
    return !id.empty();
  }
  if (s.rfind(kPfPrefix, 0) == 0) {
    prefix = kPfPrefix;
    id = s.substr(std::strlen(kPfPrefix));
    return !id.empty();
  }
  return false;
}

void atomic_write_bytes(const std::filesystem::path &path,
                        const std::vector<uint8_t> &data) {
  std::filesystem::create_directories(path.parent_path());
  chmod(path.parent_path().c_str(), 0700);
  auto tmp = path;
  tmp += ".tmp";
  {
    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char *>(data.data()),
              static_cast<std::streamsize>(data.size()));
    out.flush();
  }
  chmod(tmp.c_str(), 0600);
  std::filesystem::rename(tmp, path);
  int dirfd = ::open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY);
  if (dirfd >= 0) {
    ::fsync(dirfd);
    ::close(dirfd);
  }
}

DekWrapResult wrap_ss(const std::string &key_id,
                      const std::vector<uint8_t> &dek) {
  DekWrapResult r;
  r.provider = "secret_service";
  auto &lib = SecretServiceLoader::instance();
  if (!lib.available()) {
    r.error_code = "providerUnavailable";
    r.error_message = "libsecret unavailable";
    return r;
  }

  const std::string id = sanitize(key_id);
  SecretServiceLoader::Schema schema = {
      "flutter_secure_storage_dek",
      SecretServiceLoader::SCHEMA_NONE,
      {
          {"application-id", SecretServiceLoader::ATTR_STRING},
          {"dek-key-id", SecretServiceLoader::ATTR_STRING},
          {"record-version", SecretServiceLoader::ATTR_STRING},
      }};
  FHashTable attrs;
  attrs.insert("application-id", APPLICATION_ID);
  attrs.insert("dek-key-id", id.c_str());
  attrs.insert("record-version", "1");

  const std::string payload = b64_encode(dek);
  const std::string label =
      std::string(APPLICATION_ID) + "/dek/" + id;
  g_autoptr(GError) err = nullptr;
  bool ok = lib.storev_sync(&schema, attrs.getGHashTable(), nullptr,
                            label.c_str(), payload.c_str(), nullptr, &err);
  if (!ok || err) {
    r.error_code = "accessDenied";
    r.error_message = err ? err->message : "secret store failed";
    return r;
  }
  r.ok = true;
  r.token = make_token(kSsPrefix, id);
  return r;
}

DekWrapResult unwrap_ss(const std::string &id) {
  DekWrapResult r;
  r.provider = "secret_service";
  auto &lib = SecretServiceLoader::instance();
  if (!lib.available()) {
    r.error_code = "providerUnavailable";
    r.error_message = "libsecret unavailable";
    return r;
  }
  SecretServiceLoader::Schema schema = {
      "flutter_secure_storage_dek",
      SecretServiceLoader::SCHEMA_NONE,
      {
          {"application-id", SecretServiceLoader::ATTR_STRING},
          {"dek-key-id", SecretServiceLoader::ATTR_STRING},
          {"record-version", SecretServiceLoader::ATTR_STRING},
      }};
  FHashTable attrs;
  attrs.insert("application-id", APPLICATION_ID);
  attrs.insert("dek-key-id", id.c_str());
  attrs.insert("record-version", "1");
  g_autoptr(GError) err = nullptr;
  fss_secret_autofree gchar *result =
      lib.lookupv_sync(&schema, attrs.getGHashTable(), nullptr, &err);
  if (err) {
    r.error_code = "keyUnwrapFailed";
    r.error_message = err->message;
    return r;
  }
  if (!result || result[0] == '\0') {
    r.error_code = "keyNotFound";
    r.error_message = "wrapped DEK missing";
    return r;
  }
  r.ok = true;
  r.token = b64_decode(result);
  return r;
}

DekWrapResult delete_ss(const std::string &id) {
  DekWrapResult r;
  r.provider = "secret_service";
  auto &lib = SecretServiceLoader::instance();
  if (!lib.available()) {
    r.ok = true;
    return r;
  }
  SecretServiceLoader::Schema schema = {
      "flutter_secure_storage_dek",
      SecretServiceLoader::SCHEMA_NONE,
      {
          {"application-id", SecretServiceLoader::ATTR_STRING},
          {"dek-key-id", SecretServiceLoader::ATTR_STRING},
          {"record-version", SecretServiceLoader::ATTR_STRING},
      }};
  FHashTable attrs;
  attrs.insert("application-id", APPLICATION_ID);
  attrs.insert("dek-key-id", id.c_str());
  attrs.insert("record-version", "1");
  g_autoptr(GError) err = nullptr;
  lib.clearv_sync(&schema, attrs.getGHashTable(), nullptr, &err);
  r.ok = true;
  return r;
}

DekWrapResult wrap_pf(const std::string &key_id,
                      const std::vector<uint8_t> &dek) {
  DekWrapResult r;
  r.provider = "protected_file";
  try {
    const std::string id = sanitize(key_id);
    auto path = dek_root() / (id + ".dek");
    atomic_write_bytes(path, dek);
    r.ok = true;
    r.token = make_token(kPfPrefix, id);
  } catch (const std::exception &e) {
    r.error_code = "unsafeFilesystemPermissions";
    r.error_message = e.what();
  }
  return r;
}

DekWrapResult unwrap_pf(const std::string &id) {
  DekWrapResult r;
  r.provider = "protected_file";
  try {
    auto path = dek_root() / (sanitize(id) + ".dek");
    if (!std::filesystem::exists(path) || std::filesystem::is_symlink(path)) {
      r.error_code = "keyNotFound";
      r.error_message = "wrapped DEK file missing";
      return r;
    }
    std::ifstream in(path, std::ios::binary);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
    r.ok = true;
    r.token = std::move(data);
  } catch (const std::exception &e) {
    r.error_code = "keyUnwrapFailed";
    r.error_message = e.what();
  }
  return r;
}

DekWrapResult delete_pf(const std::string &id) {
  DekWrapResult r;
  r.provider = "protected_file";
  try {
    auto path = dek_root() / (sanitize(id) + ".dek");
    std::error_code ec;
    std::filesystem::remove(path, ec);
    r.ok = true;
  } catch (const std::exception &e) {
    r.error_code = "unknown";
    r.error_message = e.what();
  }
  return r;
}

} // namespace

DekWrapProvider select_dek_provider(bool force_protected_file) {
  if (force_protected_file) {
    return DekWrapProvider::ProtectedFile;
  }
  auto &lib = SecretServiceLoader::instance();
  if (lib.available() && SecretServiceLoader::sessionBusPresent()) {
    return DekWrapProvider::SecretService;
  }
  return DekWrapProvider::ProtectedFile;
}

DekWrapResult wrap_dek(const std::string &key_id,
                       const std::vector<uint8_t> &dek,
                       bool force_protected_file) {
  if (dek.empty()) {
    DekWrapResult r;
    r.error_code = "invalidConfiguration";
    r.error_message = "empty DEK";
    return r;
  }
  if (select_dek_provider(force_protected_file) ==
      DekWrapProvider::SecretService) {
    auto r = wrap_ss(key_id, dek);
    if (r.ok) {
      return r;
    }
    // Fall back to protected file.
  }
  return wrap_pf(key_id, dek);
}

DekWrapResult unwrap_dek(const std::vector<uint8_t> &token) {
  std::string prefix;
  std::string id;
  if (!parse_token(token, prefix, id)) {
    DekWrapResult r;
    r.error_code = "corruptRecord";
    r.error_message = "unknown DEK wrap token";
    return r;
  }
  if (prefix == kSsPrefix) {
    return unwrap_ss(id);
  }
  return unwrap_pf(id);
}

DekWrapResult delete_wrapped_dek(const std::vector<uint8_t> &token) {
  std::string prefix;
  std::string id;
  if (!parse_token(token, prefix, id)) {
    DekWrapResult r;
    r.ok = true;
    return r;
  }
  if (prefix == kSsPrefix) {
    return delete_ss(id);
  }
  return delete_pf(id);
}
