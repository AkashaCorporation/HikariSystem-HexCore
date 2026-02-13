#!/usr/bin/env python3
"""
Generate binding.gyp for hexcore-remill.
Only includes LLVM libs that actually exist on disk to avoid LNK1181.
"""
import json, os, glob

MRD = "<(module_root_dir)"
DEPS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "deps")

remill_libs = [
    "remill_bc", "remill_os", "remill_arch", "remill_arch_x86",
    "remill_arch_aarch64", "remill_arch_sparc32", "remill_arch_sparc64",
    "remill_arch_sleigh", "remill_version", "decomp", "sla", "slaSupport"
]

# Discover all LLVM .lib files that actually exist
llvm_lib_dir = os.path.join(DEPS, "llvm", "lib")
llvm_libs = []
if os.path.isdir(llvm_lib_dir):
    for f in sorted(os.listdir(llvm_lib_dir)):
        if f.startswith("LLVM") and f.endswith(".lib"):
            llvm_libs.append(f[:-4])  # strip .lib
print(f"Found {len(llvm_libs)} LLVM libs in deps/llvm/lib/")

# Verify remill libs exist
remill_lib_dir = os.path.join(DEPS, "remill", "lib")
actual_remill = []
for l in remill_libs:
    if os.path.isfile(os.path.join(remill_lib_dir, l + ".lib")):
        actual_remill.append(l)
    else:
        print(f"  WARNING: remill lib missing: {l}")
print(f"Found {len(actual_remill)} remill/sleigh libs")

# Verify xed, glog, gflags libs exist
extra_libs = []
for lib_path, label in [
    ("xed/lib/xed.lib", "xed"),
    ("xed/lib/xed-ild.lib", "xed-ild"),
    ("glog/lib/glog.lib", "glog"),
    ("gflags/lib/gflags_static.lib", "gflags"),
]:
    full = os.path.join(DEPS, lib_path)
    if os.path.isfile(full):
        extra_libs.append(f"{MRD}/deps/{lib_path}")
    else:
        print(f"  WARNING: {label} lib missing: {full}")

win_libs = (
    [f"{MRD}/deps/remill/lib/{l}.lib" for l in actual_remill] +
    [f"{MRD}/deps/llvm/lib/{l}.lib" for l in llvm_libs] +
    extra_libs
)

gyp = {
    "targets": [{
        "target_name": "hexcore_remill",
        "cflags!": ["-fno-exceptions"],
        "cflags_cc!": ["-fno-exceptions"],
        "sources": ["src/main.cpp", "src/remill_wrapper.cpp"],
        "include_dirs": [
            '<!@(node -p "require(\'node-addon-api\').include")',
            "deps/remill/include",
            "deps/llvm/include",
            "deps/xed/include",
            "deps/glog/include",
            "deps/gflags/include"
        ],
        "defines": ["NAPI_VERSION=8", "NAPI_DISABLE_CPP_EXCEPTIONS"],
        "conditions": [
            ["OS=='win'", {
                "libraries": win_libs,
                "msvs_settings": {
                    "VCCLCompilerTool": {
                        "ExceptionHandling": 1,
                        "RuntimeLibrary": 0,
                        "AdditionalOptions": ["/EHsc", "/std:c++17", "/bigobj"]
                    },
                    "VCLinkerTool": {
                        "AdditionalDependencies": [
                            "Advapi32.lib", "Shell32.lib", "Ole32.lib",
                            "Uuid.lib", "ws2_32.lib", "psapi.lib",
                            "dbghelp.lib", "version.lib", "ntdll.lib",
                            "synchronization.lib", "bcrypt.lib",
                            "Shlwapi.lib"
                        ]
                    }
                },
                "defines": [
                    "_CRT_SECURE_NO_WARNINGS", "_SCL_SECURE_NO_WARNINGS",
                    "_SILENCE_CXX17_ITERATOR_BASE_CLASS_DEPRECATION_WARNING",
                    "NOMINMAX", "GLOG_NO_ABBREVIATED_SEVERITIES",
                    "GOOGLE_GLOG_DLL_DECL=", "GFLAGS_IS_A_DLL=0",
                    "GLOG_USE_GLOG_EXPORT", "GLOG_STATIC_DEFINE"
                ]
            }],
            ["OS=='linux'", {
                "libraries": ["-lpthread", "-ldl", "-lz"],
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
