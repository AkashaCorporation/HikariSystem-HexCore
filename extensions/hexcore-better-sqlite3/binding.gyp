{
  "targets": [{
    "target_name": "hexcore_sqlite3",
    "sources": [
      "src/main.cpp",
      "src/sqlite3_wrapper.cpp"
    ],
    "include_dirs": [
      "<!@(node -p \"require('node-addon-api').include\")",
      "deps/sqlite3/include"
    ],
    "dependencies": [
      "<!(node -p \"require('node-addon-api').gyp\")"
    ],
    "defines": [
      "NAPI_VERSION=8",
      "NAPI_CPP_EXCEPTIONS",
      "NODE_ADDON_API_DISABLE_DEPRECATED"
    ],
    "cflags!": ["-fno-exceptions"],
    "cflags_cc!": ["-fno-exceptions"],
    "conditions": [
      ["OS=='win'", {
        "libraries": [
          "<(module_root_dir)/deps/sqlite3/sqlite3.lib"
        ],
        "msvs_settings": {
          "VCCLCompilerTool": {
            "ExceptionHandling": 1,
            "AdditionalOptions": ["/std:c++17"]
          }
        },
        "defines": ["_HAS_EXCEPTIONS=1"]
      }],
      ["OS=='linux'", {
        "libraries": [
          "<(module_root_dir)/deps/sqlite3/libsqlite3.a",
          "-lpthread",
          "-ldl"
        ],
        "cflags": ["-fPIC"],
        "cflags_cc": ["-fPIC", "-std=c++17", "-fexceptions"]
      }],
      ["OS=='mac'", {
        "libraries": [
          "<(module_root_dir)/deps/sqlite3/libsqlite3.a"
        ],
        "xcode_settings": {
          "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
          "CLANG_CXX_LIBRARY": "libc++",
          "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
          "MACOSX_DEPLOYMENT_TARGET": "10.15"
        }
      }]
    ]
  }]
}
