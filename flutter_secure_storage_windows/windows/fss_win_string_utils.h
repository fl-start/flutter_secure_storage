#ifndef FSS_WIN_STRING_UTILS_H_
#define FSS_WIN_STRING_UTILS_H_

#include <string>

std::wstring FssUtf8ToWide(const std::string& utf8);
std::string FssWideToUtf8(const wchar_t* wide);

inline std::string FssWideToUtf8(const std::wstring& wide) {
  return FssWideToUtf8(wide.c_str());
}

#endif  // FSS_WIN_STRING_UTILS_H_
