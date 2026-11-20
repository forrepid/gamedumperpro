cmake_minimum_required(VERSION 3.16)
project(DumperPro LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE DUMPERPRO_SOURCES CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
)

add_executable(DumperPro ${DUMPERPRO_SOURCES})
target_include_directories(DumperPro PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

if (MSVC)
    target_compile_options(DumperPro PRIVATE /W3 /permissive- /Zi /O2 /EHsc)
    target_compile_definitions(DumperPro PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    # static runtime so the tool runs without redistributables
    set_property(TARGET DumperPro PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    target_compile_options(DumperPro PRIVATE -O2 -Wall -Wextra -Wno-unused-parameter)
    if (WIN32)
        target_link_options(DumperPro PRIVATE -static -static-libgcc -static-libstdc++)
    endif()
endif()

# Windows-only tool (process reader uses WinAPI). Build natively with MSVC or MinGW-w64.
if (NOT WIN32)
    message(WARNING "DumperPro targets Windows; building on this host will exclude the Win32 reader backends.")
endif()
