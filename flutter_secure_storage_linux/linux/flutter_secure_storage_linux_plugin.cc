#include "include/flutter_secure_storage_linux/flutter_secure_storage_linux_plugin.h"
#include "include/Secret.hpp"
#include "include/dek_wrap.hpp"
#include "include/json.hpp"
#include "include/providers/protected_file_provider.hpp"
#include "include/providers/provider_select.hpp"
#include "include/secret_service_loader.hpp"
#include "include/tpm_probe.hpp"

#include <cstring>
#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

#define flutter_secure_storage_linux_plugin(obj)                               \
  (G_TYPE_CHECK_INSTANCE_CAST((obj),                                           \
                              flutter_secure_storage_linux_plugin_get_type(),   \
                              FlutterSecureStorageLinuxPlugin))

struct _FlutterSecureStorageLinuxPlugin {
  GObject parent_instance;
};

G_DEFINE_TYPE(FlutterSecureStorageLinuxPlugin,
              flutter_secure_storage_linux_plugin, g_object_get_type())

static const char *kDefaultAccountName = "flutter_secure_storage_service";

static std::map<std::string, std::unique_ptr<SecretStorage>> g_keyrings;
static std::unique_ptr<fss::ProtectedFileProvider> g_file_provider;

static fss::ProtectedFileProvider &fileProvider() {
  if (!g_file_provider) {
    g_file_provider = std::make_unique<fss::ProtectedFileProvider>(true);
  }
  return *g_file_provider;
}

static bool headlessEnvironment() {
  return !SecretServiceLoader::sessionBusPresent();
}

static bool useSecretServiceKv() {
  return fss::prefer_secret_service_kv(headlessEnvironment());
}

static SecretStorage &keyringForAccount(const std::string &accountName) {
  auto found = g_keyrings.find(accountName);
  if (found != g_keyrings.end()) {
    return *found->second;
  }

  const std::string label =
      std::string(APPLICATION_ID) + "/FlutterSecureStorage/" + accountName;
  const std::string accountAttr =
      std::string(APPLICATION_ID) + "." + accountName + ".secureStorage";

  auto storage = std::make_unique<SecretStorage>(label.c_str(), APPLICATION_ID,
                                                 accountName.c_str());
  storage->addAttribute("account", accountAttr.c_str());
  auto &ref = *storage;
  g_keyrings.emplace(accountName, std::move(storage));
  return ref;
}

static std::string parseAccountName(FlMethodCall *method_call) {
  FlValue *args = fl_method_call_get_args(method_call);
  if (args == nullptr || fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
    return kDefaultAccountName;
  }

  FlValue *options = fl_value_lookup_string(args, "options");
  if (options == nullptr || fl_value_get_type(options) != FL_VALUE_TYPE_MAP) {
    return kDefaultAccountName;
  }

  FlValue *account = fl_value_lookup_string(options, "accountName");
  if (account == nullptr || fl_value_get_type(account) != FL_VALUE_TYPE_STRING) {
    return kDefaultAccountName;
  }

  const gchar *accountString = fl_value_get_string(account);
  if (accountString == nullptr || accountString[0] == '\0') {
    return kDefaultAccountName;
  }

  return accountString;
}

static std::string flValueToString(FlValue *value) {
  if (value == nullptr) {
    return "";
  }
  if (fl_value_get_type(value) == FL_VALUE_TYPE_STRING) {
    return fl_value_get_string(value);
  }
  return "";
}

static std::vector<uint8_t> flValueToBytes(FlValue *value) {
  std::vector<uint8_t> out;
  if (value == nullptr) {
    return out;
  }
  if (fl_value_get_type(value) == FL_VALUE_TYPE_UINT8_LIST) {
    size_t len = fl_value_get_length(value);
    const uint8_t *data = fl_value_get_uint8_list(value);
    out.assign(data, data + len);
  }
  return out;
}

static FlMethodResponse *errorResponse(const char *code, const char *message,
                                       const char *provider) {
  g_autoptr(FlValue) details = fl_value_new_map();
  if (provider) {
    fl_value_set_string_take(details, "provider",
                             fl_value_new_string(provider));
  }
  return FL_METHOD_RESPONSE(
      fl_method_error_response_new(code, message, details));
}

static void kvWrite(const std::string &account, const gchar *key,
                    const gchar *value) {
  if (useSecretServiceKv()) {
    try {
      keyringForAccount(account).addItem(key, value);
      return;
    } catch (...) {
      // Fall through to protected file.
    }
  }
  fileProvider().write(account, key, value);
}

static FlValue *kvRead(const std::string &account, const gchar *key) {
  if (useSecretServiceKv()) {
    try {
      auto str = keyringForAccount(account).getItem(key);
      if (!str.empty()) {
        return fl_value_new_string(str.c_str());
      }
    } catch (...) {
      // Fall through.
    }
  }
  auto opt = fileProvider().read(account, key);
  if (!opt.has_value()) {
    return nullptr;
  }
  return fl_value_new_string(opt->c_str());
}

static FlValue *kvReadAll(const std::string &account) {
  FlValue *result = fl_value_new_map();
  if (useSecretServiceKv()) {
    try {
      auto data = keyringForAccount(account).readAllItems();
      for (const auto &each : data) {
        fl_value_set_string_take(result, each.first.c_str(),
                                 fl_value_new_string(each.second.c_str()));
      }
      return result;
    } catch (...) {
      fl_value_unref(result);
      result = fl_value_new_map();
    }
  }
  auto data = fileProvider().readAll(account);
  for (const auto &each : data) {
    fl_value_set_string_take(result, each.first.c_str(),
                             fl_value_new_string(each.second.c_str()));
  }
  return result;
}

static void kvDelete(const std::string &account, const gchar *key) {
  if (useSecretServiceKv()) {
    try {
      keyringForAccount(account).deleteItem(key);
    } catch (...) {
    }
  }
  fileProvider().remove(account, key);
}

static void kvDeleteAll(const std::string &account) {
  if (useSecretServiceKv()) {
    try {
      keyringForAccount(account).deleteKeyring();
    } catch (...) {
    }
  }
  fileProvider().removeAll(account);
}

static FlValue *kvContains(const std::string &account, const gchar *key) {
  if (useSecretServiceKv()) {
    try {
      auto value = keyringForAccount(account).getItem(key);
      if (!value.empty()) {
        return fl_value_new_bool(TRUE);
      }
    } catch (...) {
    }
  }
  return fl_value_new_bool(fileProvider().contains(account, key));
}

static void flutter_secure_storage_linux_plugin_handle_method_call(
    FlutterSecureStorageLinuxPlugin *self, FlMethodCall *method_call) {
  g_autoptr(FlMethodResponse) response = nullptr;

  const gchar *method = fl_method_call_get_name(method_call);
  FlValue *args = fl_method_call_get_args(method_call);

  if (fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
    response = FL_METHOD_RESPONSE(fl_method_error_response_new(
        "Bad arguments", "args given to function is not a map", nullptr));
  } else {
    FlValue *key = fl_value_lookup_string(args, "key");
    FlValue *value = fl_value_lookup_string(args, "value");
    const gchar *keyString = key == nullptr ? nullptr : fl_value_get_string(key);
    const gchar *valueString =
        value == nullptr ? nullptr : fl_value_get_string(value);
    const std::string account = parseAccountName(method_call);

    try {
      if (strcmp(method, "write") == 0) {
        if (!keyString || !valueString) {
          response = FL_METHOD_RESPONSE(fl_method_error_response_new(
              "Bad arguments", "Key or Value was null", nullptr));
        } else {
          kvWrite(account, keyString, valueString);
          response =
              FL_METHOD_RESPONSE(fl_method_success_response_new(nullptr));
        }
      } else if (strcmp(method, "read") == 0) {
        if (!keyString) {
          response = FL_METHOD_RESPONSE(fl_method_error_response_new(
              "Bad arguments", "Key is null", nullptr));
        } else {
          g_autoptr(FlValue) result = kvRead(account, keyString);
          response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));
        }
      } else if (strcmp(method, "readAll") == 0) {
        g_autoptr(FlValue) result = kvReadAll(account);
        response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));
      } else if (strcmp(method, "delete") == 0) {
        if (!keyString) {
          response = FL_METHOD_RESPONSE(fl_method_error_response_new(
              "Bad arguments", "Key is null", nullptr));
        } else {
          kvDelete(account, keyString);
          response =
              FL_METHOD_RESPONSE(fl_method_success_response_new(nullptr));
        }
      } else if (strcmp(method, "deleteAll") == 0) {
        kvDeleteAll(account);
        response = FL_METHOD_RESPONSE(fl_method_success_response_new(nullptr));
      } else if (strcmp(method, "containsKey") == 0) {
        if (!keyString) {
          response = FL_METHOD_RESPONSE(fl_method_error_response_new(
              "Bad arguments", "Key is null", nullptr));
        } else {
          g_autoptr(FlValue) result = kvContains(account, keyString);
          response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));
        }
      } else {
        response = FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());
      }
    } catch (const std::string &e) {
      g_warning("linux_secure_storage_error: %s", e.c_str());
      response = FL_METHOD_RESPONSE(
          fl_method_error_response_new("LinuxStorageError", e.c_str(), nullptr));
    } catch (const std::exception &e) {
      g_warning("linux_secure_storage_error: %s", e.what());
      response = FL_METHOD_RESPONSE(
          fl_method_error_response_new("LinuxStorageError", e.what(), nullptr));
    }
  }
  fl_method_call_respond(method_call, response, nullptr);
}

static FlValue *buildCapabilities(FlValue *args) {
  std::string protection = "platformDefault";
  if (args && fl_value_get_type(args) == FL_VALUE_TYPE_MAP) {
    FlValue *p = fl_value_lookup_string(args, "protection");
    if (p && fl_value_get_type(p) == FL_VALUE_TYPE_STRING) {
      protection = fl_value_get_string(p);
    }
  }

  const bool secret = SecretServiceLoader::instance().available();
  const bool session = SecretServiceLoader::sessionBusPresent();
  const bool tpm = fss_probe_tpm2_available();
  const bool headless = !session;

  FlValue *map = fl_value_new_map();
  fl_value_set_string_take(map, "platform", fl_value_new_string("linux"));

  FlValue *providers = fl_value_new_list();
  if (secret) {
    fl_value_append_take(providers, fl_value_new_string("secret_service"));
  }
  fl_value_append_take(providers, fl_value_new_string("protected_file"));
  if (tpm) {
    fl_value_append_take(providers, fl_value_new_string("tpm2_optional"));
  }
  fl_value_set_string_take(map, "availableProviders", providers);

  std::string selected = "protected_file";
  std::string fallback;
  gboolean hardwareAvailable = tpm ? TRUE : FALSE;
  gboolean storageHw = FALSE;
  gboolean privateHw = FALSE;

  if (protection == "hardwareBackedRequired") {
    selected = tpm ? "tpm2_optional" : "none";
    storageHw = FALSE; // TPM key path not implemented yet
    privateHw = FALSE;
    if (!tpm) {
      fallback = "TPM2 ESAPI unavailable";
    } else {
      fallback = "TPM2 private-key path not implemented";
    }
  } else if (protection == "hardwareBackedPreferred") {
    if (tpm) {
      selected = secret && session ? "secret_service" : "protected_file";
      fallback = "TPM2 private-key path not implemented; using software wrap";
    } else if (secret && session && !headless) {
      selected = "secret_service";
      fallback = "TPM / libtss2-esys unavailable";
    } else {
      selected = "protected_file";
      fallback = "TPM unavailable; Secret Service unavailable or headless";
    }
  } else if (protection == "softwareProtected") {
    selected = "protected_file";
  } else {
    // platformDefault
    if (secret && session && !headless) {
      selected = "secret_service";
    } else {
      selected = "protected_file";
      if (!secret) {
        fallback = "libsecret unavailable";
      } else if (headless) {
        fallback = "no D-Bus session bus; using protected file";
      }
    }
  }

  fl_value_set_string_take(map, "selectedProvider",
                           fl_value_new_string(selected.c_str()));
  fl_value_set_string_take(map, "hardwareAvailable",
                           fl_value_new_bool(hardwareAvailable));
  fl_value_set_string_take(map, "storageProtectionHardwareBacked",
                           fl_value_new_bool(storageHw));
  fl_value_set_string_take(map, "privateKeyHardwareBacked",
                           fl_value_new_bool(privateHw));
  fl_value_set_string_take(map, "supportsNonExportableKeys",
                           fl_value_new_bool(TRUE));
  fl_value_set_string_take(map, "supportsExportableKeys",
                           fl_value_new_bool(TRUE));
  fl_value_set_string_take(map, "supportsUserPresence",
                           fl_value_new_bool(FALSE));
  fl_value_set_string_take(map, "supportsMachineScope",
                           fl_value_new_bool(FALSE));
  fl_value_set_string_take(map, "supportsCsrGeneration",
                           fl_value_new_bool(TRUE));

  FlValue *algs = fl_value_new_list();
  fl_value_append_take(algs, fl_value_new_string("rsa2048"));
  fl_value_append_take(algs, fl_value_new_string("rsa3072"));
  fl_value_append_take(algs, fl_value_new_string("ecP256"));
  fl_value_append_take(algs, fl_value_new_string("ed25519"));
  fl_value_set_string_take(map, "supportedAlgorithms", algs);

  FlValue *formats = fl_value_new_list();
  fl_value_append_take(formats, fl_value_new_string("pemPkcs8"));
  fl_value_append_take(formats, fl_value_new_string("derPkcs8"));
  fl_value_set_string_take(map, "supportedExportFormats", formats);

  if (!fallback.empty()) {
    fl_value_set_string_take(map, "fallbackReason",
                             fl_value_new_string(fallback.c_str()));
  }
  fl_value_set_string_take(map, "sameUserCompromiseResistant",
                           fl_value_new_bool(FALSE));
  fl_value_set_string_take(map, "rootCompromiseResistant",
                           fl_value_new_bool(FALSE));
  return map;
}

static void desktop_keys_method_call_cb(FlMethodChannel *channel,
                                        FlMethodCall *method_call,
                                        gpointer user_data) {
  const gchar *method = fl_method_call_get_name(method_call);
  FlValue *args = fl_method_call_get_args(method_call);
  g_autoptr(FlMethodResponse) response = nullptr;

  if (strcmp(method, "getCapabilities") == 0) {
    g_autoptr(FlValue) map = buildCapabilities(args);
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(map));
  } else if (strcmp(method, "wrapDek") == 0) {
    if (!args || fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
      response = errorResponse("invalidConfiguration", "bad args", "linux");
    } else {
      std::string keyId = flValueToString(fl_value_lookup_string(args, "keyId"));
      auto dek = flValueToBytes(fl_value_lookup_string(args, "dek"));
      FlValue *force = fl_value_lookup_string(args, "forceProtectedFile");
      bool forcePf = force && fl_value_get_type(force) == FL_VALUE_TYPE_BOOL &&
                     fl_value_get_bool(force);
      auto result = wrap_dek(keyId, dek, forcePf);
      if (!result.ok) {
        response = errorResponse(result.error_code.c_str(),
                                 result.error_message.c_str(),
                                 result.provider.c_str());
      } else {
        g_autoptr(FlValue) map = fl_value_new_map();
        fl_value_set_string_take(
            map, "token",
            fl_value_new_uint8_list(result.token.data(), result.token.size()));
        fl_value_set_string_take(map, "provider",
                                 fl_value_new_string(result.provider.c_str()));
        response = FL_METHOD_RESPONSE(fl_method_success_response_new(map));
      }
    }
  } else if (strcmp(method, "unwrapDek") == 0) {
    if (!args || fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
      response = errorResponse("invalidConfiguration", "bad args", "linux");
    } else {
      auto token = flValueToBytes(fl_value_lookup_string(args, "token"));
      auto result = unwrap_dek(token);
      if (!result.ok) {
        response = errorResponse(result.error_code.c_str(),
                                 result.error_message.c_str(),
                                 result.provider.c_str());
      } else {
        g_autoptr(FlValue) map = fl_value_new_map();
        fl_value_set_string_take(
            map, "dek",
            fl_value_new_uint8_list(result.token.data(), result.token.size()));
        fl_value_set_string_take(map, "provider",
                                 fl_value_new_string(result.provider.c_str()));
        response = FL_METHOD_RESPONSE(fl_method_success_response_new(map));
      }
    }
  } else if (strcmp(method, "deleteWrapped") == 0) {
    if (!args || fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
      response = errorResponse("invalidConfiguration", "bad args", "linux");
    } else {
      auto token = flValueToBytes(fl_value_lookup_string(args, "token"));
      auto result = delete_wrapped_dek(token);
      if (!result.ok) {
        response = errorResponse(result.error_code.c_str(),
                                 result.error_message.c_str(),
                                 result.provider.c_str());
      } else {
        response =
            FL_METHOD_RESPONSE(fl_method_success_response_new(nullptr));
      }
    }
  } else {
    // create/sign/export handled by Dart LinuxDesktopKeyManager.
    response = FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());
  }
  fl_method_call_respond(method_call, response, nullptr);
}

static void flutter_secure_storage_linux_plugin_dispose(GObject *object) {
  G_OBJECT_CLASS(flutter_secure_storage_linux_plugin_parent_class)
      ->dispose(object);
}

static void flutter_secure_storage_linux_plugin_class_init(
    FlutterSecureStorageLinuxPluginClass *klass) {
  G_OBJECT_CLASS(klass)->dispose = flutter_secure_storage_linux_plugin_dispose;
}

static void
flutter_secure_storage_linux_plugin_init(FlutterSecureStorageLinuxPlugin *self) {
}

static void method_call_cb(FlMethodChannel *channel, FlMethodCall *method_call,
                           gpointer user_data) {
  FlutterSecureStorageLinuxPlugin *plugin =
      flutter_secure_storage_linux_plugin(user_data);
  flutter_secure_storage_linux_plugin_handle_method_call(plugin, method_call);
}

void flutter_secure_storage_linux_plugin_register_with_registrar(
    FlPluginRegistrar *registrar) {
  FlutterSecureStorageLinuxPlugin *plugin = flutter_secure_storage_linux_plugin(
      g_object_new(flutter_secure_storage_linux_plugin_get_type(), nullptr));

  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
  g_autoptr(FlMethodChannel) channel = fl_method_channel_new(
      fl_plugin_registrar_get_messenger(registrar),
      "plugins.it_nomads.com/flutter_secure_storage", FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(
      channel, method_call_cb, g_object_ref(plugin), g_object_unref);

  g_autoptr(FlStandardMethodCodec) desktop_codec =
      fl_standard_method_codec_new();
  g_autoptr(FlMethodChannel) desktop_channel = fl_method_channel_new(
      fl_plugin_registrar_get_messenger(registrar),
      "plugins.it_nomads.com/flutter_secure_storage/desktop_keys",
      FL_METHOD_CODEC(desktop_codec));
  fl_method_channel_set_method_call_handler(
      desktop_channel, desktop_keys_method_call_cb, g_object_ref(plugin),
      g_object_unref);

  g_object_unref(plugin);
}
