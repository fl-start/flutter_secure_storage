#include "include/tpm_probe.hpp"

#include <dlfcn.h>

bool fss_probe_tpm2_available() {
  static const char *kCandidates[] = {
      "libtss2-esys.so.0",
      "libtss2-esys.so",
  };
  for (const char *name : kCandidates) {
    void *lib = dlopen(name, RTLD_LAZY | RTLD_LOCAL);
    if (!lib) {
      continue;
    }
    void *sym = dlsym(lib, "Esys_Initialize");
    dlclose(lib);
    if (sym) {
      return true;
    }
  }
  return false;
}
