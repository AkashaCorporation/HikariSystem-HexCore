{
	"targets": [
		{
			"target_name": "hexcore_keystone",
			"cflags!": ["-fno-exceptions"],
			"cflags_cc!": ["-fno-exceptions"],
			"cflags_cc": ["-std=c++17"],
			"sources": [
				"src/main.cpp",
				"src/keystone_wrapper.cpp"
			],
			"include_dirs": [
				"<!@(node -p \"require('node-addon-api').include\")",
				"deps/keystone/include"
			],
			"defines": [
				"NAPI_DISABLE_CPP_EXCEPTIONS",
				"NODE_ADDON_API_ENABLE_MAYBE"
			],
			"conditions": [
				["OS=='win'", {
					"libraries": [
						"<(module_root_dir)/deps/keystone/build_new/Release/keystone.lib"
					],
					"msvs_settings": {
						"VCCLCompilerTool": {
							"ExceptionHandling": 1,
							"AdditionalOptions": ["/std:c++17", "/MD"],
							"RuntimeLibrary": 2
						}
					}
				}],
				["OS=='linux'", {
					"libraries": [
						"-L<(module_root_dir)/deps/keystone/lib",
						"-lkeystone",
						"-Wl,-rpath,<(module_root_dir)/deps/keystone/lib"
					],
					"cflags_cc": ["-std=c++17", "-fexceptions"]
				}],
				["OS=='mac'", {
					"libraries": [
						"-L<(module_root_dir)/deps/keystone/lib",
						"-lkeystone"
					],
					"xcode_settings": {
						"GCC_ENABLE_CPP_EXCEPTIONS": "YES",
						"CLANG_CXX_LIBRARY": "libc++",
						"CLANG_CXX_LANGUAGE_STANDARD": "c++17",
						"OTHER_LDFLAGS": [
							"-Wl,-rpath,@loader_path"
						]
					}
				}]
			]
		}
	]
}
