// ============================================================================
// DumperPro - Unreal Engine Memory / SDK Dumper
// framework.h - common includes + base types
//
// Intended use: offline analysis, single-player modding, engine research and
// interoperability on software you own or are licensed to analyze.
// ============================================================================
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <functional>
#include <optional>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <chrono>
#include <mutex>
#include <atomic>

namespace dumper {

using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i8  = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;

namespace fs = std::filesystem;

// small format helper used across the codebase
std::string Hex(u64 v);          // "0x00007FF6ABCD1234"
std::string Hex32(u32 v);        // "0x00000ABC"

} // namespace dumper
