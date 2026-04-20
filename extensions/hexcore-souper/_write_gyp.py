#!/usr/bin/env python3
"""
Generate binding.gyp for hexcore-souper.
Only includes libs that actually exist on disk to avoid LNK1181.
Same pattern as hexcore-remill/_write_gyp.py.
"""
import json, os

MRD = "<(module_root_dir)"
DEPS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "deps")

# Souper libs we expect
souper_lib_names = [
    "souperExtractor", "souperInfer", "souperInst", "souperKVStore",
    "souperParser", "souperSMTLIB2", "souperTool", "souperCodegen",
    "kleeExpr",
]

# Alive2 libs
alive2_lib_names = ["ir", "smt", "tools", "util"]

# Discover LLVM .lib files that exist
llvm_lib_dir = os.path.join(DEPS, "llvm", "lib")
llvm_libs = []
if os.path.isdir(llvm_lib_dir):
    for f in sorted(os.listdir(llvm_lib_dir)):
        if f.startswith("LLVM") and f.endswith(".lib"):
            llvm_libs.append(f[:-4])
print(f"Found {len(llvm_libs)} LLVM libs in deps/llvm/lib/")

# Verify souper libs exist
souper_lib_dir = os.path.join(DEPS, "souper", "lib")
actual_souper = []
for l in souper_lib_names:
    if os.path.isfile(os.path.join(souper_lib_dir, l + ".lib")):
        actual_souper.append(l)
    else:
        print(f"  WARNING: souper lib missing: {l}")
print(f"Found {len(actual_souper)} souper libs")

# Verify alive2 libs
alive2_lib_dir = os.path.join(DEPS, "alive2", "lib")
actual_alive2 = []
for l in alive2_lib_names:
    if os.path.isfile(os.path.join(alive2_lib_dir, l + ".lib")):
        actual_alive2.append(l)
    else:
        print(f"  WARNING: alive2 lib missing: {l}")
print(f"Found {len(actual_alive2)} alive2 libs")

# Z3
z3_lib = os.path.join(DEPS, "z3", "lib", "libz3.lib")
has_z3 = os.path.isfile(z3_lib)
print(f"Z3: {'found' if has_z3 else 'MISSING'}")

# hiredis (optional)
hiredis_lib = os.path.join(DEPS, "hiredis", "lib", "hiredis.lib")
has_hiredis = os.path.isfile(hiredis_lib)

# Build the full library list
win_libs = (
    [f"{MRD}/deps/souper/lib/{l}.lib" for l in actual_souper] +
    [f"{MRD}/deps/alive2/lib/{l}.lib" for l in actual_alive2] +
    [f"{MRD}/deps/llvm/lib/{l}.lib" for l in llvm_libs] +
    ([f"{MRD}/deps/z3/lib/libz3.lib"] if has_z3 else []) +
    ([f"{MRD}/deps/hiredis/lib/hiredis.lib"] if has_hiredis else [])
)

gyp = {
    "targets": [{
        "target_name": "hexcore_souper",
        "cflags!": ["-fno-exceptions"],
        "cflags_cc!": ["-fno-exceptions"],
        "sources": ["src/main.cpp", "src/souper_wrapper.cpp"],
        "include_dirs": [
            '<!@(node -p "require(\'node-addon-api\').include")',
            "deps/souper/include",
            "deps/alive2/include",
            "deps/klee/include",
            "deps/llvm/include",
            "deps/z3/include"
        ],
        "defines": ["NAPI_VERSION=8", "NAPI_DISABLE_CPP_EXCEPTIONS"],
        "conditions": [
            ["OS=='win'", {
                "libraries": win_libs,
                "msvs_settings": {
                    "VCCLCompilerTool": {
                        "ExceptionHandling": 1,
                        "RuntimeLibrary": 0,  # /MT
                        "AdditionalOptions": ["/EHsc", "/std:c++17", "/bigobj"]
                    },
                    "VCLinkerTool": {
                        "AdditionalDependencies": [
                            "Advapi32.lib", "Shell32.lib", "Ole32.lib",
                            "Uuid.lib", "ws2_32.lib", "psapi.lib",
                            "dbghelp.lib", "version.lib", "ntdll.lib",
                            "synchronization.lib", "bcrypt.lib",
                            "Shlwapi.lib"
                        ],
                        "AdditionalOptions": ["/STACK:8388608"]
                    }
                },
                "defines": [
                    "_CRT_SECURE_NO_WARNINGS", "_SCL_SECURE_NO_WARNINGS",
                    "NOMINMAX"
                ]
            }],
            ["OS=='linux'", {
                "libraries": ["-lz3", "-lpthread", "-ldl", "-lm"],
                "cflags": ["-fPIC"],
                "cflags_cc": ["-fPIC", "-std=c++17", "-fexceptions"]
            }],
            ["OS=='mac'", {
                "xcode_settings": {
                    "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
                    "CLANG_CXX_LIBRARY": "libc++",
                    "MACOSX_DEPLOYMENT_TARGET": "10.15",
                    "OTHER_CPLUSPLUSFLAGS": ["-std=c++17"]
                }
            }]
        ]
    }]
}

out = os.path.join(os.path.dirname(__file__), "binding.gyp")
with open(out, "w", encoding="utf-8") as f:
    json.dump(gyp, f, indent=2)
print(f"Wrote {os.path.getsize(out)} bytes to {out}")
print(f"Total win libs: {len(win_libs)}")
