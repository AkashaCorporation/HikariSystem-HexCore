{
  "targets": [
    {
      "target_name": "hexcore_rellic",
      "cflags!": [
        "-fno-exceptions"
      ],
      "cflags_cc!": [
        "-fno-exceptions"
      ],
      "sources": [
        "src/main.cpp",
        "src/rellic_wrapper.cpp",
        "src/rellic_passes.cpp",
        "src/rellic_decompile_pipeline.cpp",
        "src/rellic_opaque_ptr.cpp",
        "src/rellic_llvm_compat.cpp"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "deps/llvm/include"
      ],
      "defines": [
        "NAPI_VERSION=8",
        "NAPI_DISABLE_CPP_EXCEPTIONS"
      ],
      "conditions": [
        [
          "OS=='win'",
          {
            "libraries": [
              "<(module_root_dir)/deps/llvm/lib/LLVMCore.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMSupport.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMIRReader.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMAsmParser.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMBitReader.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMBitstreamReader.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMAnalysis.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMTransformUtils.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMIRPrinter.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMObject.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMBinaryFormat.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMMC.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMMCParser.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMProfileData.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMRemarks.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMDemangle.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMTargetParser.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMTextAPI.lib"
            ],
            "msvs_settings": {
              "VCCLCompilerTool": {
                "ExceptionHandling": 1,
                "RuntimeLibrary": 0,
                "AdditionalOptions": [
                  "/EHsc",
                  "/std:c++17",
                  "/bigobj"
                ]
              },
              "VCLinkerTool": {
                "AdditionalDependencies": [
                  "Advapi32.lib",
                  "Shell32.lib",
                  "Ole32.lib",
                  "Uuid.lib",
                  "ws2_32.lib",
                  "psapi.lib",
                  "dbghelp.lib",
                  "version.lib",
                  "ntdll.lib",
                  "synchronization.lib",
                  "bcrypt.lib",
                  "Shlwapi.lib"
                ]
              }
            },
            "defines": [
              "_CRT_SECURE_NO_WARNINGS",
              "_SCL_SECURE_NO_WARNINGS",
              "_SILENCE_CXX17_ITERATOR_BASE_CLASS_DEPRECATION_WARNING",
              "NOMINMAX"
            ]
          }
        ],
        [
          "OS=='linux'",
          {
            "libraries": [
              "-lpthread",
              "-ldl",
              "-lz"
            ],
            "cflags": [
              "-fPIC"
            ],
            "cflags_cc": [
              "-fPIC",
              "-std=c++17",
              "-fexceptions"
            ]
          }
        ],
        [
          "OS=='mac'",
          {
            "xcode_settings": {
              "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
              "CLANG_CXX_LIBRARY": "libc++",
              "MACOSX_DEPLOYMENT_TARGET": "10.15",
              "OTHER_CPLUSPLUSFLAGS": [
                "-std=c++17"
              ]
            }
          }
        ]
      ]
    }
  ]
}
