#include "include/secret_service_loader.hpp"

#include <dlfcn.h>

#include <cstdlib>

SecretServiceLoader &SecretServiceLoader::instance() {
  static SecretServiceLoader loader;
  return loader;
}

bool SecretServiceLoader::sessionBusPresent() {
  const char *addr = getenv("DBUS_SESSION_BUS_ADDRESS");
  return addr != nullptr && addr[0] != '\0';
}

SecretServiceLoader::SecretServiceLoader() {
  static const char *kCandidates[] = {
      "libsecret-1.so.0",
      "libsecret-1.so",
  };
  for (const char *name : kCandidates) {
    lib_ = dlopen(name, RTLD_LAZY | RTLD_LOCAL);
    if (lib_) {
      break;
    }
  }
  if (!lib_) {
    return;
  }

  store_ = reinterpret_cast<StoreFn>(
      dlsym(lib_, "secret_password_storev_sync"));
  lookup_ = reinterpret_cast<LookupFn>(
      dlsym(lib_, "secret_password_lookupv_sync"));
  clear_ = reinterpret_cast<ClearFn>(
      dlsym(lib_, "secret_password_clearv_sync"));
  free_ =
      reinterpret_cast<FreeFn>(dlsym(lib_, "secret_password_free"));

  available_ = store_ && lookup_ && clear_ && free_;
  if (!available_) {
    dlclose(lib_);
    lib_ = nullptr;
    store_ = nullptr;
    lookup_ = nullptr;
    clear_ = nullptr;
    free_ = nullptr;
  }
}

gboolean SecretServiceLoader::storev_sync(const Schema *schema,
                                          GHashTable *attributes,
                                          const gchar *collection,
                                          const gchar *label,
                                          const gchar *password,
                                          GCancellable *cancellable,
                                          GError **error) const {
  if (!available_ || !store_) {
    if (error) {
      *error = g_error_new_literal(g_quark_from_static_string("fss-secret"), 1,
                                   "libsecret unavailable");
    }
    return FALSE;
  }
  return store_(schema, attributes, collection, label, password, cancellable,
                error);
}

gchar *SecretServiceLoader::lookupv_sync(const Schema *schema,
                                         GHashTable *attributes,
                                         GCancellable *cancellable,
                                         GError **error) const {
  if (!available_ || !lookup_) {
    if (error) {
      *error = g_error_new_literal(g_quark_from_static_string("fss-secret"), 1,
                                   "libsecret unavailable");
    }
    return nullptr;
  }
  return lookup_(schema, attributes, cancellable, error);
}

gboolean SecretServiceLoader::clearv_sync(const Schema *schema,
                                          GHashTable *attributes,
                                          GCancellable *cancellable,
                                          GError **error) const {
  if (!available_ || !clear_) {
    if (error) {
      *error = g_error_new_literal(g_quark_from_static_string("fss-secret"), 1,
                                   "libsecret unavailable");
    }
    return FALSE;
  }
  return clear_(schema, attributes, cancellable, error);
}

void SecretServiceLoader::password_free(gchar *password) const {
  if (password && free_) {
    free_(password);
  } else {
    g_free(password);
  }
}
