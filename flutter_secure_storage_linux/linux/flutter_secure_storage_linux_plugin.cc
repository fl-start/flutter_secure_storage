#include "include/flutter_secure_storage_linux/flutter_secure_storage_linux_plugin.h"
#include "include/Secret.hpp"
#include "include/json.hpp"

#include <cstring>
#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>
#include <libsecret/secret.h>
#include <map>
#include <memory>
#include <string>
#include <sys/utsname.h>

#define flutter_secure_storage_linux_plugin(obj)                                     \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), flutter_secure_storage_linux_plugin_get_type(), \
                              FlutterSecureStorageLinuxPlugin))

struct _FlutterSecureStorageLinuxPlugin
{
  GObject parent_instance;
};

G_DEFINE_TYPE(FlutterSecureStorageLinuxPlugin, flutter_secure_storage_linux_plugin,
              g_object_get_type())

static const char *kDefaultAccountName = "flutter_secure_storage_service";

static std::map<std::string, std::unique_ptr<SecretStorage>> g_keyrings;

static SecretStorage &keyringForAccount(const std::string &accountName)
{
  auto found = g_keyrings.find(accountName);
  if (found != g_keyrings.end())
  {
    return *found->second;
  }

  const std::string label =
      std::string(APPLICATION_ID) + "/FlutterSecureStorage/" + accountName;
  const std::string accountAttr =
      std::string(APPLICATION_ID) + "." + accountName + ".secureStorage";

  auto storage = std::make_unique<SecretStorage>(
      label.c_str(), APPLICATION_ID, accountName.c_str());
  storage->addAttribute("account", accountAttr.c_str());
  auto &ref = *storage;
  g_keyrings.emplace(accountName, std::move(storage));
  return ref;
}

static std::string parseAccountName(FlMethodCall *method_call)
{
  FlValue *args = fl_method_call_get_args(method_call);
  if (args == nullptr || fl_value_get_type(args) != FL_VALUE_TYPE_MAP)
  {
    return kDefaultAccountName;
  }

  FlValue *options = fl_value_lookup_string(args, "options");
  if (options == nullptr || fl_value_get_type(options) != FL_VALUE_TYPE_MAP)
  {
    return kDefaultAccountName;
  }

  FlValue *account = fl_value_lookup_string(options, "accountName");
  if (account == nullptr || fl_value_get_type(account) != FL_VALUE_TYPE_STRING)
  {
    return kDefaultAccountName;
  }

  const gchar *accountString = fl_value_get_string(account);
  if (accountString == nullptr || accountString[0] == '\0')
  {
    return kDefaultAccountName;
  }

  return accountString;
}

static void deleteIt(SecretStorage &keyring, const gchar *key)
{
  keyring.deleteItem(key);
}

static void deleteAll(SecretStorage &keyring) { keyring.deleteKeyring(); }

static void write(SecretStorage &keyring, const gchar *key, const gchar *value)
{
  keyring.addItem(key, value);
}

static FlValue *read(SecretStorage &keyring, const gchar *key)
{
  auto str = keyring.getItem(key);
  if (str == "")
  {
    return nullptr;
  }
  return fl_value_new_string(str.c_str());
}

static FlValue *readAll(SecretStorage &keyring)
{
  FlValue *result = fl_value_new_map();
  auto data = keyring.readAllItems();
  for (const auto &each : data)
  {
    fl_value_set_string_take(result, each.first.c_str(),
                             fl_value_new_string(each.second.c_str()));
  }
  return result;
}

static FlValue *containsKey(SecretStorage &keyring, const gchar *key)
{
  auto value = keyring.getItem(key);
  return fl_value_new_bool(!value.empty());
}

// Called when a method call is received from Flutter.
static void flutter_secure_storage_linux_plugin_handle_method_call(
    FlutterSecureStorageLinuxPlugin *self, FlMethodCall *method_call)
{
  g_autoptr(FlMethodResponse) response = nullptr;

  const gchar *method = fl_method_call_get_name(method_call);
  FlValue *args = fl_method_call_get_args(method_call);

  if (fl_value_get_type(args) != FL_VALUE_TYPE_MAP)
  {
    response = FL_METHOD_RESPONSE(fl_method_error_response_new(
        "Bad arguments", "args given to function is not a map", nullptr));
  }
  else
  {
    FlValue *key = fl_value_lookup_string(args, "key");
    FlValue *value = fl_value_lookup_string(args, "value");
    const gchar *keyString =
        key == nullptr ? nullptr : fl_value_get_string(key);
    const gchar *valueString =
        value == nullptr ? nullptr : fl_value_get_string(value);

    try
    {
      SecretStorage &keyring = keyringForAccount(parseAccountName(method_call));

      if (strcmp(method, "write") == 0)
      {
        if (!keyString || !valueString)
        {
          response = FL_METHOD_RESPONSE(fl_method_error_response_new(
              "Bad arguments", "Key or Value was null", nullptr));
        }
        else
        {
          write(keyring, keyString, valueString);
          response =
              FL_METHOD_RESPONSE(fl_method_success_response_new(nullptr));
        }
      }
      else if (strcmp(method, "read") == 0)
      {
        if (!keyString)
        {
          response = FL_METHOD_RESPONSE(fl_method_error_response_new(
              "Bad arguments", "Key is null", nullptr));
        }
        else
        {
          g_autoptr(FlValue) result = read(keyring, keyString);
          response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));
        }
      }
      else if (strcmp(method, "readAll") == 0)
      {
        g_autoptr(FlValue) result = readAll(keyring);
        response =
            FL_METHOD_RESPONSE(fl_method_success_response_new(result));
      }
      else if (strcmp(method, "delete") == 0)
      {
        if (!keyString)
        {
          response = FL_METHOD_RESPONSE(fl_method_error_response_new(
              "Bad arguments", "Key is null", nullptr));
        }
        else
        {
          deleteIt(keyring, keyString);
          response =
              FL_METHOD_RESPONSE(fl_method_success_response_new(nullptr));
        }
      }
      else if (strcmp(method, "deleteAll") == 0)
      {
        deleteAll(keyring);
        response = FL_METHOD_RESPONSE(fl_method_success_response_new(nullptr));
      }
      else if (strcmp(method, "containsKey") == 0)
      {
        if (!keyString)
        {
          response = FL_METHOD_RESPONSE(fl_method_error_response_new(
              "Bad arguments", "Key is null", nullptr));
        }
        else
        {
          g_autoptr(FlValue) result = containsKey(keyring, keyString);
          response = FL_METHOD_RESPONSE(fl_method_success_response_new(result));
        }
      }
      else
      {
        response = FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());
      }
    }
    catch (const std::string &e)
    {
      g_warning("libsecret_error: %s", e.c_str());
      response = FL_METHOD_RESPONSE(
          fl_method_error_response_new("Libsecret error", e.c_str(), nullptr));
    }
    catch (const std::exception &e)
    {
      g_warning("libsecret_error: %s", e.what());
      response = FL_METHOD_RESPONSE(
          fl_method_error_response_new("Libsecret error", e.what(), nullptr));
    }
    fl_method_call_respond(method_call, response, nullptr);
  }
}

static void flutter_secure_storage_linux_plugin_dispose(GObject *object)
{
  G_OBJECT_CLASS(flutter_secure_storage_linux_plugin_parent_class)->dispose(object);
}

static void flutter_secure_storage_linux_plugin_class_init(
    FlutterSecureStorageLinuxPluginClass *klass)
{
  G_OBJECT_CLASS(klass)->dispose = flutter_secure_storage_linux_plugin_dispose;
}

static void
flutter_secure_storage_linux_plugin_init(FlutterSecureStorageLinuxPlugin *self) {}

static void method_call_cb(FlMethodChannel *channel, FlMethodCall *method_call,
                           gpointer user_data)
{
  FlutterSecureStorageLinuxPlugin *plugin = flutter_secure_storage_linux_plugin(user_data);
  flutter_secure_storage_linux_plugin_handle_method_call(plugin, method_call);
}

static void desktop_keys_method_call_cb(FlMethodChannel *channel,
                                        FlMethodCall *method_call,
                                        gpointer user_data)
{
  const gchar *method = fl_method_call_get_name(method_call);
  g_autoptr(FlMethodResponse) response = nullptr;

  if (strcmp(method, "getCapabilities") == 0)
  {
    g_autoptr(FlValue) map = fl_value_new_map();
    fl_value_set_string_take(map, "platform", fl_value_new_string("linux"));

    FlValue *providers = fl_value_new_list();
    fl_value_append_take(providers, fl_value_new_string("secret_service"));
    fl_value_append_take(providers, fl_value_new_string("protected_file"));
    fl_value_append_take(providers, fl_value_new_string("tpm2_optional"));
    fl_value_append_take(providers, fl_value_new_string("systemd_creds_optional"));
    fl_value_set_string_take(map, "availableProviders", providers);

    fl_value_set_string_take(map, "selectedProvider",
                             fl_value_new_string("secret_service"));
    fl_value_set_string_take(map, "hardwareAvailable", fl_value_new_bool(FALSE));
    fl_value_set_string_take(map, "storageProtectionHardwareBacked",
                             fl_value_new_bool(FALSE));
    fl_value_set_string_take(map, "privateKeyHardwareBacked",
                             fl_value_new_bool(FALSE));
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

    fl_value_set_string_take(map, "sameUserCompromiseResistant",
                             fl_value_new_bool(FALSE));
    fl_value_set_string_take(map, "rootCompromiseResistant",
                             fl_value_new_bool(FALSE));
    response = FL_METHOD_RESPONSE(fl_method_success_response_new(map));
  }
  else
  {
    response = FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());
  }
  fl_method_call_respond(method_call, response, nullptr);
}

void flutter_secure_storage_linux_plugin_register_with_registrar(
    FlPluginRegistrar *registrar)
{
  FlutterSecureStorageLinuxPlugin *plugin = flutter_secure_storage_linux_plugin(
      g_object_new(flutter_secure_storage_linux_plugin_get_type(), nullptr));

  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
  g_autoptr(FlMethodChannel) channel = fl_method_channel_new(
      fl_plugin_registrar_get_messenger(registrar),
      "plugins.it_nomads.com/flutter_secure_storage", FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(
      channel, method_call_cb, g_object_ref(plugin), g_object_unref);

  g_autoptr(FlStandardMethodCodec) desktop_codec = fl_standard_method_codec_new();
  g_autoptr(FlMethodChannel) desktop_channel = fl_method_channel_new(
      fl_plugin_registrar_get_messenger(registrar),
      "plugins.it_nomads.com/flutter_secure_storage/desktop_keys",
      FL_METHOD_CODEC(desktop_codec));
  fl_method_channel_set_method_call_handler(
      desktop_channel, desktop_keys_method_call_cb, g_object_ref(plugin),
      g_object_unref);

  g_object_unref(plugin);
}
