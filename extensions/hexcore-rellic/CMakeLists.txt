# ============================================================
# HexCore Rellic - Static Library Build (CMake)
#
# Builds the ported Rellic decompilation passes as a static
# library (rellic.lib / librellic.a) for linking into the
# hexcore_rellic N-API module via binding.gyp.
#
# This CMakeLists.txt is NOT for the N-API module itself —
# that is built by node-gyp using binding.gyp.  This file
# builds only the Rellic pass library.
#
# Prerequisites:
#   - LLVM 18.1.8 built/installed (LLVM_DIR must be set)
#   - Clang 18.1.8 built/installed (Clang_DIR must be set)
#   - Z3 4.12+ built/installed (Z3_DIR must be set)
#
# Usage:
#   cmake -G Ninja -S . -B build-rellic \
#     -DCMAKE_BUILD_TYPE=Release \
#     -DLLVM_DIR=deps/llvm/lib/cmake/llvm \
#     -DClang_DIR=deps/clang/lib/cmake/clang \
#     -DZ3_DIR=deps/z3/lib/cmake/z3
#   cmake --build build-rellic
#
# Copyright (c) HikariSystem. All rights reserved.
# Licensed under MIT License.
# ============================================================

cmake_minimum_required(VERSION 3.21)

project(hexcore-rellic-lib
    VERSION 1.0.0
    DESCRIPTION "HexCore Rellic decompilation passes (LLVM 18)"
    LANGUAGES CXX
)

# ---- C++ standard ----
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---- Static library only ----
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static library only" FORCE)

# ---- Find dependencies ----
find_package(LLVM 18.1 REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

# Z3 — try find_package first, fall back to manual paths
find_package(Z3 4.12 QUIET CONFIG)
if(NOT Z3_FOUND)
    message(STATUS "Z3 not found via CMake config, using manual paths")
    # Manual Z3 discovery for builds where Z3 has no CMake config
    if(DEFINED Z3_INCLUDE_DIR AND DEFINED Z3_LIBRARY)
        message(STATUS "Using manual Z3: ${Z3_INCLUDE_DIR}, ${Z3_LIBRARY}")
    else()
        # Default to deps/ layout
        set(Z3_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/deps/z3/include" CACHE PATH "Z3 include dir")
        if(WIN32)
            set(Z3_LIBRARY "${CMAKE_CURRENT_SOURCE_DIR}/deps/z3/lib/libz3.lib" CACHE FILEPATH "Z3 library")
        else()
            set(Z3_LIBRARY "${CMAKE_CURRENT_SOURCE_DIR}/deps/z3/lib/libz3.a" CACHE FILEPATH "Z3 library")
        endif()
    endif()
endif()

message(STATUS "LLVM version: ${LLVM_VERSION}")
message(STATUS "LLVM include dirs: ${LLVM_INCLUDE_DIRS}")
message(STATUS "Clang include dirs: ${CLANG_INCLUDE_DIRS}")

# ---- LLVM definitions ----
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

# ---- Rellic static library ----
# Sources: passes, pipeline, opaque pointer utils, LLVM compat layer
# NOTE: rellic_wrapper.cpp and main.cpp are NOT included here —
#       those are N-API specific and built by binding.gyp.
add_library(rellic STATIC
    src/rellic_passes.cpp
    src/rellic_decompile_pipeline.cpp
    src/rellic_opaque_ptr.cpp
    src/rellic_llvm_compat.cpp
)

target_include_directories(rellic PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LLVM_INCLUDE_DIRS}
)

# Clang include dirs (may be set by find_package or manual)
if(DEFINED CLANG_INCLUDE_DIRS)
    target_include_directories(rellic PUBLIC ${CLANG_INCLUDE_DIRS})
else()
    target_include_directories(rellic PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/clang/include
    )
endif()

# Z3 include dirs
if(Z3_FOUND AND TARGET z3::libz3)
    target_link_libraries(rellic PUBLIC z3::libz3)
elseif(DEFINED Z3_INCLUDE_DIR)
    target_include_directories(rellic PUBLIC ${Z3_INCLUDE_DIR})
    if(DEFINED Z3_LIBRARY)
        target_link_libraries(rellic PUBLIC ${Z3_LIBRARY})
    endif()
endif()

# LLVM libraries needed by the passes
llvm_map_components_to_libnames(LLVM_LIBS
    Core
    Support
    IRReader
    AsmParser
    Passes
    Analysis
    TransformUtils
    ScalarOpts
)
target_link_libraries(rellic PUBLIC ${LLVM_LIBS})

# Clang libraries needed for AST generation
set(CLANG_LIBS
    clangAST
    clangBasic
    clangLex
    clangSema
    clangFrontend
    clangSerialization
    clangDriver
    clangParse
    clangEdit
    clangAnalysis
)

foreach(lib ${CLANG_LIBS})
    if(TARGET ${lib})
        target_link_libraries(rellic PUBLIC ${lib})
    else()
        # Fall back to manual library path
        if(WIN32)
            set(_lib_path "${CMAKE_CURRENT_SOURCE_DIR}/deps/clang/lib/${lib}.lib")
        else()
            set(_lib_path "${CMAKE_CURRENT_SOURCE_DIR}/deps/clang/lib/lib${lib}.a")
        endif()
        if(EXISTS "${_lib_path}")
            target_link_libraries(rellic PUBLIC "${_lib_path}")
        else()
            message(WARNING "Clang library not found: ${lib}")
        endif()
    endif()
endforeach()

# ---- Platform-specific flags ----
if(MSVC OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" AND WIN32)
    target_compile_options(rellic PRIVATE
        /EHsc
        /bigobj
        /W3
    )
    target_compile_definitions(rellic PRIVATE
        _CRT_SECURE_NO_WARNINGS
        _SCL_SECURE_NO_WARNINGS
        _SILENCE_CXX17_ITERATOR_BASE_CLASS_DEPRECATION_WARNING
        NOMINMAX
    )
    # Use /MT (static CRT) to match LLVM/Clang/Z3 libs
    set_property(TARGET rellic PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )
else()
    target_compile_options(rellic PRIVATE
        -fPIC
        -fexceptions
        -Wall
        -Wextra
        -Wno-unused-parameter
    )
endif()

# ---- Install rules ----
# Copies headers and lib to deps/rellic/ for binding.gyp consumption
install(TARGETS rellic
    ARCHIVE DESTINATION lib
)

install(FILES
    src/rellic_passes.h
    src/rellic_decompile_pipeline.h
    src/rellic_opaque_ptr.h
    src/rellic_llvm_compat.h
    DESTINATION include/rellic
)

# ---- Summary ----
message(STATUS "")
message(STATUS "=== HexCore Rellic Static Library ===")
message(STATUS "  C++ standard:  C++${CMAKE_CXX_STANDARD}")
message(STATUS "  Build type:    ${CMAKE_BUILD_TYPE}")
message(STATUS "  LLVM version:  ${LLVM_VERSION}")
message(STATUS "  Output:        rellic (static)")
message(STATUS "  Sources:       rellic_passes.cpp, rellic_decompile_pipeline.cpp,")
message(STATUS "                 rellic_opaque_ptr.cpp, rellic_llvm_compat.cpp")
message(STATUS "=====================================")
message(STATUS "")
