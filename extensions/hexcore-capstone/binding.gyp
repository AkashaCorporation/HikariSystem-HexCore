{
  "targets": [
    {
      "target_name": "capstone_native",
      "sources": [
        "src/main.cpp",
        "src/capstone_wrapper.cpp"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "deps/capstone/include"
      ],
      "defines": [
        "NAPI_VERSION=8",
        "NAPI_DISABLE_CPP_EXCEPTIONS"
      ],
      "conditions": [
        ["OS=='win'", {
          "libraries": [
            "<(module_root_dir)/deps/capstone/build/Release/capstone.lib"
          ],
          "msvs_settings": {
            "VCCLCompilerTool": {
              "ExceptionHandling": 1,
              "AdditionalIncludeDirectories": [
                "<(module_root_dir)/deps/capstone/include"
              ]
            }
          }
        }],
        ["OS=='linux'", {
          "libraries": [
            "<(module_root_dir)/deps/capstone/build/libcapstone.a"
          ],
          "cflags": ["-fPIC"],
          "cflags_cc": ["-fPIC", "-std=c++17"]
        }],
        ["OS=='mac'", {
          "libraries": [
            "<(module_root_dir)/deps/capstone/build/libcapstone.a"
          ],
          "xcode_settings": {
            "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
            "CLANG_CXX_LIBRARY": "libc++",
            "MACOSX_DEPLOYMENT_TARGET": "10.15"
          }
        }]
      ]
    }
  ]
}
