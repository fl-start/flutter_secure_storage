#pragma once

#include <glib.h>

#include <mutex>
#include <string>

/// Soft-loads libsecret at runtime via dlopen. Builds do not link -lsecret.
class SecretServiceLoader {
public:
  static SecretServiceLoader &instance();

  /// True when libsecret-1.so was loaded and required symbols resolved.
  bool available() const { return available_; }

  /// True when a session D-Bus bus looks present (interactive keyring likely).
  static bool sessionBusPresent();

  // Minimal SecretSchema layout matching libsecret >= 0.18.
  enum AttributeType { ATTR_STRING = 0 };
  enum SchemaFlags { SCHEMA_NONE = 0 };

  struct SchemaAttribute {
    const gchar *name;
    AttributeType type;
  };

  struct Schema {
    const gchar *name;
    SchemaFlags flags;
    SchemaAttribute attributes[32];
  };

  gboolean storev_sync(const Schema *schema, GHashTable *attributes,
                       const gchar *collection, const gchar *label,
                       const gchar *password, GCancellable *cancellable,
                       GError **error) const;

  gchar *lookupv_sync(const Schema *schema, GHashTable *attributes,
                      GCancellable *cancellable, GError **error) const;

  gboolean clearv_sync(const Schema *schema, GHashTable *attributes,
                       GCancellable *cancellable, GError **error) const;

  void password_free(gchar *password) const;

private:
  SecretServiceLoader();
  SecretServiceLoader(const SecretServiceLoader &) = delete;
  SecretServiceLoader &operator=(const SecretServiceLoader &) = delete;

  void *lib_ = nullptr;
  bool available_ = false;

  using StoreFn = gboolean (*)(const void *, GHashTable *, const gchar *,
                               const gchar *, const gchar *, GCancellable *,
                               GError **);
  using LookupFn = gchar *(*)(const void *, GHashTable *, GCancellable *,
                              GError **);
  using ClearFn = gboolean (*)(const void *, GHashTable *, GCancellable *,
                               GError **);
  using FreeFn = void (*)(gchar *);

  StoreFn store_ = nullptr;
  LookupFn lookup_ = nullptr;
  ClearFn clear_ = nullptr;
  FreeFn free_ = nullptr;
};

#define fss_secret_autofree                                                        \
  _GLIB_CLEANUP(fss_secret_cleanup_free)
static inline void fss_secret_cleanup_free(gchar **p) {
  if (p && *p) {
    SecretServiceLoader::instance().password_free(*p);
    *p = nullptr;
  }
}
