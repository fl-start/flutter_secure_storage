#include "FHashTable.hpp"
#include "json.hpp"
#include <libsecret/secret.h>
#include <memory>
#include <string>

#define secret_autofree _GLIB_CLEANUP(secret_cleanup_free)
static inline void secret_cleanup_free(gchar **p) { secret_password_free(*p); }

class SecretStorage {
  FHashTable m_attributes;
  std::string label;
  SecretSchema the_schema;

  // Rebuilds the schema so that `the_schema.name` points at the current
  // `label` storage. Must be called whenever `label` changes.
  void rebuildSchema() {
    the_schema = {label.c_str(),
                  SECRET_SCHEMA_NONE,
                  {
                      {"account", SECRET_SCHEMA_ATTRIBUTE_STRING},
                  }};
  }

public:
  // `the_schema.name` holds a pointer into `label`; copying/moving would
  // dangle it. Instances are owned via pointers (see the plugin's keyring map).
  SecretStorage(const SecretStorage &) = delete;
  SecretStorage &operator=(const SecretStorage &) = delete;
  SecretStorage(SecretStorage &&) = delete;
  SecretStorage &operator=(SecretStorage &&) = delete;

  const char *getLabel() { return label.c_str(); }
  void setLabel(const char *label) {
    this->label = label;
    rebuildSchema();
  }

  SecretStorage(const char *_label = "default") : label(_label) {
    rebuildSchema();
  }

  void addAttribute(const char *key, const char *value) {
    m_attributes.insert(key, value);
  }

  bool addItem(const char *key, const char *value) {
    nlohmann::json root = readFromKeyring();
    root[key] = value;
    return storeToKeyring(root);
  }

  std::string getItem(const char *key) {
    std::string result;
    nlohmann::json root = readFromKeyring();
    nlohmann::json value = root[key];
    if(value.is_string()){
      result = value.get<std::string>();
      return result;
    }
    return "";
  }

  void deleteItem(const char *key) {
    try {
      nlohmann::json root = readFromKeyring();
      if (root.is_null()) {
          return;
      }
      root.erase(key);
      storeToKeyring(root);
    } catch (const std::exception& e) {
        return;
    }
  }

  bool deleteKeyring() { return this->storeToKeyring(nlohmann::json()); }

  bool storeToKeyring(nlohmann::json value) {
    const std::string output = value.dump();
    g_autoptr(GError) err = nullptr;
    bool result = secret_password_storev_sync(
        &the_schema, m_attributes.getGHashTable(), nullptr, label.c_str(),
        output.c_str(), nullptr, &err);

    if (err) {
      // Copy the message: `err` is freed by g_autoptr as the stack unwinds,
      // so throwing `err->message` directly would dangle.
      throw std::string(err->message);
    }

    return result;
  }

  nlohmann::json readFromKeyring() {
    nlohmann::json value;
    g_autoptr(GError) err = nullptr;

    warmupKeyring();

    secret_autofree gchar *result = secret_password_lookupv_sync(
        &the_schema, m_attributes.getGHashTable(), nullptr, &err);

    if (err) {
      throw std::string(err->message);
    }
    if(result != NULL && strcmp(result, "") != 0){
      value = nlohmann::json::parse(result);
    }
    return value;
  }

private:
  // Search with schemas fails in cold keyrings.
  // https://gitlab.gnome.org/GNOME/gnome-keyring/-/issues/89
  //
  // Note that we're not using the workaround mentioned in the above issue. Instead, we're using
  // a workaround as implemented in http://crbug.com/660005. Reason being that with the lookup
  // approach we can't distinguish whether the keyring was actually unlocked or whether the user
  // cancelled the password prompt.
  //
  // The keyring only needs to be unlocked once per process, so guard the dummy
  // write with a static flag to avoid an extra store (and possible prompt) on
  // every read/contains/delete.
  void warmupKeyring() {
    static bool warmedUp = false;
    if (warmedUp) {
      return;
    }

    g_autoptr(GError) err = nullptr;

    FHashTable attributes;
    attributes.insert("explanation", "Because of quirks in the gnome libsecret API, "
            "flutter_secret_storage needs to store a dummy entry to guarantee that "
            "this keyring was properly unlocked. More details at http://crbug.com/660005.");

    const gchar* dummy_label = "FlutterSecureStorage Control";

    // Store a dummy entry without `the_schema`.
    bool success = secret_password_storev_sync(
        NULL, attributes.getGHashTable(), nullptr, dummy_label,
        "The meaning of life", nullptr, &err);

    if (!success) {
      throw std::string("Failed to unlock the keyring");
    }

    warmedUp = true;
  }
};
