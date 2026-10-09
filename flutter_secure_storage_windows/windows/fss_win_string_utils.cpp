#include "fss_win_string_utils.h"

#include <windows.h>

namespace {

std::wstring Utf8BytesToWide(const char* bytes, int byte_len) {
  if (bytes == nullptr || byte_len <= 0) {
    return {};
  }
  const int wchar_len = MultiByteToWideChar(
      CP_UTF8, MB_ERR_INVALID_CHARS, bytes, byte_len, nullptr, 0);
  if (wchar_len <= 0) {
    return {};
  }
  std::wstring wide(static_cast<size_t>(wchar_len), L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes, byte_len,
                          wide.data(), wchar_len) == 0) {
    return {};
  }
  return wide;
}

std::string WideCharsToUtf8(const wchar_t* wide, int wchar_len) {
  if (wide == nullptr || wchar_len <= 0) {
    return {};
  }
  const int byte_len = WideCharToMultiByte(
      CP_UTF8, WC_ERR_INVALID_CHARS, wide, wchar_len, nullptr, 0, nullptr,
      nullptr);
  if (byte_len <= 0) {
    return {};
  }
  std::string utf8(static_cast<size_t>(byte_len), '\0');
  if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, wchar_len,
                          utf8.data(), byte_len, nullptr, nullptr) == 0) {
    return {};
  }
  return utf8;
}

}  // namespace

std::wstring FssUtf8ToWide(const std::string& utf8) {
  return Utf8BytesToWide(utf8.data(), static_cast<int>(utf8.size()));
}

std::string FssWideToUtf8(const wchar_t* wide) {
  if (wide == nullptr) {
    return {};
  }
  return WideCharsToUtf8(wide, static_cast<int>(wcslen(wide)));
}
