{
  "targets": [
    {
      "target_name": "hexcore_unicorn",
      "sources": [
        "src/main.cpp",
        "src/unicorn_wrapper.cpp"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "deps/unicorn/include"
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
            "<(module_root_dir)/deps/unicorn/unicorn-import.lib"
          ],
          "copies": [
            {
              "destination": "<(module_root_dir)/build/Release/",
              "files": [
                "<(module_root_dir)/deps/unicorn/unicorn.dll"
              ]
            }
          ],
          "msvs_settings": {
            "VCCLCompilerTool": {
              "ExceptionHandling": 1,
              "AdditionalOptions": ["/std:c++17"]
            }
          },
          "defines": [
            "_HAS_EXCEPTIONS=1"
          ]
        }],
        ["OS=='linux'", {
          "libraries": [
            "-L<(module_root_dir)/deps/unicorn",
            "-lunicorn",
            "-Wl,-rpath,'$$ORIGIN'"
          ],
          "cflags_cc": [
            "-std=c++17",
            "-fexceptions"
          ],
          "copies": [
            {
              "destination": "<(module_root_dir)/build/Release/",
              "files": [
                "<(module_root_dir)/deps/unicorn/libunicorn.so",
                "<(module_root_dir)/deps/unicorn/libunicorn.so.2"
              ]
            }
          ]
        }],
        ["OS=='mac'", {
          "libraries": [
            "-L<(module_root_dir)/deps/unicorn",
            "-lunicorn",
            "-Wl,-rpath,@loader_path"
          ],
          "xcode_settings": {
            "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
            "CLANG_CXX_LIBRARY": "libc++",
            "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
            "MACOSX_DEPLOYMENT_TARGET": "10.15"
          },
          "copies": [
            {
              "destination": "<(module_root_dir)/build/Release/",
              "files": [
                "<(module_root_dir)/deps/unicorn/libunicorn.dylib",
                "<(module_root_dir)/deps/unicorn/libunicorn.2.dylib"
              ]
            }
          ]
        }]
      ]
    }
  ]
}
