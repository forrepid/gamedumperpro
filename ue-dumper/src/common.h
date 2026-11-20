// ============================================================================
//  UnrealDumperX - common.h
//  Shared types and small utilities used across the whole dumper.
//  Target: Windows x64, C++20, UE4 4.20-4.27 / UE5 5.0-5.3
// ============================================================================
#pragma once

#define UDX_VERSION_STRING "1.0.0"

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <algorithm>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <set>
#include <optional>
#include <string>
#include <vector>

namespace udx {

using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i8  = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;
using usize = size_t;

// printf-style formatting helper (safe, grows the buffer as needed).
std::string fmt(const char* pattern, ...);

// String helpers.
std::string trim(const std::string& s);
std::string lower(std::string s);
std::string upper(std::string s);
bool startsWith(const std::string& s, const std::string& prefix);
bool endsWith(const std::string& s, const std::string& suffix);
std::vector<std::string> split(const std::string& s, char delim);
std::string join(const std::vector<std::string>& parts, const std::string& sep);
std::string replaceAll(std::string s, const std::string& from, const std::string& to);

// Hex formatting: "0x1234ABCD" / zero-padded "0x000000001234ABCD".
std::string toHex(u64 value);
std::string toHexPadded(u64 value);

// C identifier sanitisation for SDK output ("FourCC:X" -> "FourCC_X").
std::string sanitizeIdent(std::string name);

// Filesystem helpers.
bool ensureDir(const std::string& path);
bool writeTextFile(const std::string& path, const std::string& content);
std::string timestamp();   // "%H:%M:%S"

// UTF-16 -> UTF-8 conversion for wide strings read out of the target process.
std::string wideToUtf8(const std::wstring& wide);

} // namespace udx
