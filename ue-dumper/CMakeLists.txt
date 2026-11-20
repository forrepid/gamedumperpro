# ============================================================================
#  UnrealDumperX - CMakeLists.txt
#  Build (MSVC / VS2022):
#      cmake -B build -G "Visual Studio 17 2022" -A x64
#      cmake --build build --config Release
#  Build (MinGW-w64 / clang-cl):
#      cmake -B build -G Ninja -DCMAKE_CXX_COMPILER=clang-cl
#      cmake --build build
# ============================================================================
cmake_minimum_required(VERSION 3.20)
project(UnrealDumperX VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(UnrealDumperX
    src/common.cpp
    src/ini.cpp
    src/process.cpp
    src/driver.cpp
    src/pattern.cpp
    src/version.cpp
    src/offsets.cpp
    src/fname.cpp
    src/finder.cpp
    src/classparse.cpp
    src/sdkgen.cpp
    src/vtable.cpp
    src/outputs.cpp
    src/main.cpp
)

target_include_directories(UnrealDumperX PRIVATE src)

target_compile_definitions(UnrealDumperX PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
    _CRT_SECURE_NO_WARNINGS
)

if (MSVC)
    target_compile_options(UnrealDumperX PRIVATE
        /W4 /permissive- /EHsc /O2 /Zi
    )
    target_link_options(UnrealDumperX PRIVATE
        /SUBSYSTEM:CONSOLE
    )
else()
    # MinGW-w64: link the WinAPI stack explicitly.
    target_link_options(UnrealDumperX PRIVATE
        -municode -static -static-libgcc -static-libstdc++
    )
    target_link_libraries(UnrealDumperX PRIVATE psapi user32)
endif()

# The kernel driver (driver/udxdrv.c) builds as a separate WDK project;
# this CMake tree intentionally only produces the user-mode tool.
message(STATUS "UnrealDumperX configured - driver/udxdrv.c needs the WDK")
