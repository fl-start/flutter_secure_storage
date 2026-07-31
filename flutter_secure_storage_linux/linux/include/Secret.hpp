#pragma once

#include "FHashTable.hpp"
#include "json.hpp"
#include "secret_service_loader.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

#ifndef APPLICATION_ID
#define APPLICATION_ID "flutter_secure_storage"
#endif

/// Secret Service backend with per-key items and legacy JSON migration.
///
/// Uses soft-loaded libsecret (see SecretServiceLoader). Callers must check
/// SecretServiceLoader::instance().available() before use.
class SecretStorage {
  FHashTable m_attributes;
  std::string label;
  std::string index_label;
  std::string application_id;
  std::string account_name;
  SecretServiceLoader::Schema the_schema{};
  SecretServiceLoader::Schema item_schema{};
  SecretServiceLoader::Schema index_schema{};
  bool migrated_ = false;

  void rebuildSchema() {
    index_label = label + "/index";
    the_schema = {label.c_str(),
                  SecretServiceLoader::SCHEMA_NONE,
                  {
                      {"account", SecretServiceLoader::ATTR_STRING},
                  }};
    item_schema = {"flutter_secure_storage_item",
                   SecretServiceLoader::SCHEMA_NONE,
                   {
                       {"application-id", SecretServiceLoader::ATTR_STRING},
                       {"account-name", SecretServiceLoader::ATTR_STRING},
                       {"storage-key-hash", SecretServiceLoader::ATTR_STRING},
                       {"record-version", SecretServiceLoader::ATTR_STRING},
                   }};
    index_schema = {index_label.c_str(),
                    SecretServiceLoader::SCHEMA_NONE,
                    {
                        {"account", SecretServiceLoader::ATTR_STRING},
                    }};
  }

  static std::string hashKey(const char *key) {
    uint64_t h = 14695981039346656037ull;
    for (const unsigned char *p = (const unsigned char *)key; *p; ++p) {
      h ^= *p;
      h *= 1099511628211ull;
    }
    char buf[17];
    snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)h);
    return std::string(buf);
  }

  SecretServiceLoader &lib() const { return SecretServiceLoader::instance(); }

public:
  SecretStorage(const SecretStorage &) = delete;
  SecretStorage &operator=(const SecretStorage &) = delete;
  SecretStorage(SecretStorage &&) = delete;
  SecretStorage &operator=(SecretStorage &&) = delete;

  const char *getLabel() { return label.c_str(); }
  void setLabel(const char *new_label) {
    this->label = new_label;
    rebuildSchema();
  }

  SecretStorage(const char *_label = "default",
                const char *_application_id = APPLICATION_ID,
                const char *_account_name = "flutter_secure_storage_service")
      : label(_label), application_id(_application_id),
        account_name(_account_name) {
    rebuildSchema();
  }

  void addAttribute(const char *key, const char *value) {
    m_attributes.insert(key, value);
  }

  bool addItem(const char *key, const char *value) {
    ensureMigrated();
    return storeItem(key, value);
  }

  std::string getItem(const char *key) {
    ensureMigrated();
    g_autoptr(GError) err = nullptr;
    FHashTable attrs;
    attrs.insert("application-id", application_id.c_str());
    attrs.insert("account-name", account_name.c_str());
    attrs.insert("storage-key-hash", hashKey(key).c_str());
    attrs.insert("record-version", "2");

    fss_secret_autofree gchar *result = lib().lookupv_sync(
        &item_schema, attrs.getGHashTable(), nullptr, &err);
    if (err) {
      throw std::string(err->message);
    }
    if (result == NULL) {
      return "";
    }
    return std::string(result);
  }

  void deleteItem(const char *key) {
    ensureMigrated();
    g_autoptr(GError) err = nullptr;
    FHashTable attrs;
    attrs.insert("application-id", application_id.c_str());
    attrs.insert("account-name", account_name.c_str());
    attrs.insert("storage-key-hash", hashKey(key).c_str());
    attrs.insert("record-version", "2");
    lib().clearv_sync(&item_schema, attrs.getGHashTable(), nullptr, &err);
    if (err) {
      throw std::string(err->message);
    }
  }

  bool deleteKeyring() {
    ensureMigrated();
    auto all = readAllItems();
    for (const auto &entry : all) {
      deleteItem(entry.first.c_str());
    }
    return storeToKeyring(nlohmann::json());
  }

  bool storeToKeyring(nlohmann::json value) {
    const std::string output = value.dump();
    g_autoptr(GError) err = nullptr;
    bool result = lib().storev_sync(&the_schema, m_attributes.getGHashTable(),
                                    nullptr, label.c_str(), output.c_str(),
                                    nullptr, &err);

    if (err) {
      throw std::string(err->message);
    }
    return result;
  }

  nlohmann::json readFromKeyring() {
    nlohmann::json value;
    g_autoptr(GError) err = nullptr;

    warmupKeyring();

    fss_secret_autofree gchar *result = lib().lookupv_sync(
        &the_schema, m_attributes.getGHashTable(), nullptr, &err);

    if (err) {
      throw std::string(err->message);
    }
    if (result != NULL && strcmp(result, "") != 0) {
      value = nlohmann::json::parse(result);
    }
    return value;
  }

  std::map<std::string, std::string> readAllItems() {
    ensureMigrated();
    nlohmann::json index = readIndex();
    std::map<std::string, std::string> out;
    if (!index.is_object()) {
      return out;
    }
    for (auto it = index.begin(); it != index.end(); ++it) {
      auto value = getItem(it.key().c_str());
      if (!value.empty()) {
        out[it.key()] = value;
      }
    }
    return out;
  }

private:
  bool storeItem(const char *key, const char *value) {
    g_autoptr(GError) err = nullptr;
    FHashTable attrs;
    attrs.insert("application-id", application_id.c_str());
    attrs.insert("account-name", account_name.c_str());
    attrs.insert("storage-key-hash", hashKey(key).c_str());
    attrs.insert("record-version", "2");

    std::string item_label = label + "/" + hashKey(key);
    bool ok = lib().storev_sync(&item_schema, attrs.getGHashTable(), nullptr,
                                item_label.c_str(), value, nullptr, &err);
    if (err) {
      throw std::string(err->message);
    }
    nlohmann::json index = readIndex();
    if (!index.is_object()) {
      index = nlohmann::json::object();
    }
    index[key] = true;
    writeIndex(index);
    return ok;
  }

  std::string indexAccountAttr() const {
    return application_id + "." + account_name + ".secureStorage.index";
  }

  nlohmann::json readIndex() {
    g_autoptr(GError) err = nullptr;
    FHashTable attrs;
    const std::string account_attr = indexAccountAttr();
    attrs.insert("account", account_attr.c_str());
    fss_secret_autofree gchar *result = lib().lookupv_sync(
        &index_schema, attrs.getGHashTable(), nullptr, &err);
    if (err || result == NULL || strcmp(result, "") == 0) {
      return nlohmann::json::object();
    }
    return nlohmann::json::parse(result);
  }

  void writeIndex(const nlohmann::json &index) {
    g_autoptr(GError) err = nullptr;
    FHashTable attrs;
    const std::string account_attr = indexAccountAttr();
    attrs.insert("account", account_attr.c_str());
    const std::string payload = index.dump();
    bool ok = lib().storev_sync(&index_schema, attrs.getGHashTable(), nullptr,
                                index_label.c_str(), payload.c_str(), nullptr,
                                &err);
    if (!ok || err) {
      throw std::string(err ? err->message : "failed to write index");
    }
  }

  void ensureMigrated() {
    if (migrated_) {
      return;
    }
    warmupKeyring();
    nlohmann::json legacy = readFromKeyring();
    if (!legacy.is_object() || legacy.empty()) {
      migrated_ = true;
      return;
    }

    std::vector<std::string> verified;
    for (auto it = legacy.begin(); it != legacy.end(); ++it) {
      if (!it.value().is_string()) {
        continue;
      }
      const std::string key = it.key();
      const std::string value = it.value().get<std::string>();
      storeItem(key.c_str(), value.c_str());
      auto roundtrip = getItem(key.c_str());
      if (roundtrip != value) {
        throw std::string(
            "migrationFailed: verification mismatch for key hash");
      }
      verified.push_back(key);
    }

    if (verified.size() == legacy.size()) {
      storeToKeyring(nlohmann::json());
    }
    migrated_ = true;
  }

  void warmupKeyring() {
    static bool warmedUp = false;
    if (warmedUp) {
      return;
    }

    g_autoptr(GError) err = nullptr;

    FHashTable attributes;
    attributes.insert(
        "explanation",
        "Because of quirks in the gnome libsecret API, "
        "flutter_secret_storage needs to store a dummy entry to guarantee that "
        "this keyring was properly unlocked. More details at "
        "http://crbug.com/660005.");

    const gchar *dummy_label = "FlutterSecureStorage Control";

    bool success = lib().storev_sync(nullptr, attributes.getGHashTable(),
                                     nullptr, dummy_label, "The meaning of life",
                                     nullptr, &err);

    if (!success) {
      throw std::string("Failed to unlock the keyring");
    }

    warmedUp = true;
  }
};
