cmake_minimum_required(VERSION 3.10)
set(PROJECT_NAME "flutter_secure_storage_linux")
project(${PROJECT_NAME} LANGUAGES CXX)

# This value is used when generating builds using this plugin, so it must
# not be changed
set(PLUGIN_NAME "flutter_secure_storage_linux_plugin")

add_definitions(-DAPPLICATION_ID="${APPLICATION_ID}")

add_library(${PLUGIN_NAME} SHARED
  "flutter_secure_storage_linux_plugin.cc"
  "src/secret_service_loader.cc"
  "src/tpm_probe.cc"
  "src/dek_wrap.cc"
)
apply_standard_settings(${PLUGIN_NAME})

# libsecret is soft-loaded at runtime via dlopen — do not hard-link.
# Build succeeds without libsecret-1-dev.

set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden)

target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)
target_include_directories(${PLUGIN_NAME} PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}")
target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries(${PLUGIN_NAME} PRIVATE flutter)
target_link_libraries(${PLUGIN_NAME} PRIVATE PkgConfig::GTK)
# dlopen/dlsym
target_link_libraries(${PLUGIN_NAME} PRIVATE ${CMAKE_DL_LIBS})

# List of absolute paths to libraries that should be bundled with the plugin
set(flutter_secure_storage_bundled_libraries
  ""
  PARENT_SCOPE
)
