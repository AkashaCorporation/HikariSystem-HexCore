param(
	[int]$MaxOldSpaceMB = 12288,
	[switch]$SkipExtensionInstalls
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Step {
	param([string]$Command)
	Write-Host ">> $Command" -ForegroundColor Cyan
	& powershell -NoProfile -ExecutionPolicy Bypass -Command $Command
	if ($LASTEXITCODE -ne 0) {
		throw "Command failed: $Command"
	}
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repoRoot

if (-not (Test-Path (Join-Path $repoRoot "gulpfile.mjs"))) {
	throw "Run this script from the repository root."
}

$env:VSCODE_SKIP_NODE_VERSION_CHECK = "1"
$env:NODE_OPTIONS = "--max-old-space-size=$MaxOldSpaceMB"
$env:npm_command = "ci"

Invoke-Step "npm ci"
Invoke-Step "npm ci --prefix build"
Invoke-Step "node scripts/verify-hexcore-preflight.cjs"

if (-not $SkipExtensionInstalls) {
	Invoke-Step "npm ci --prefix extensions --ignore-scripts"

	$extensionDirs = @(
		"extensions/configuration-editing",
		"extensions/css-language-features",
		"extensions/css-language-features/server",
		"extensions/debug-auto-launch",
		"extensions/debug-server-ready",
		"extensions/emmet",
		"extensions/extension-editing",
		"extensions/git",
		"extensions/git-base",
		"extensions/github",
		"extensions/github-authentication",
		"extensions/grunt",
		"extensions/gulp",
		"extensions/html-language-features",
		"extensions/html-language-features/server",
		"extensions/ipynb",
		"extensions/jake",
		"extensions/json-language-features",
		"extensions/json-language-features/server",
		"extensions/markdown-language-features",
		"extensions/markdown-math",
		"extensions/media-preview",
		"extensions/merge-conflict",
		"extensions/mermaid-chat-features",
		"extensions/microsoft-authentication",
		"extensions/npm",
		"extensions/php-language-features",
		"extensions/references-view",
		"extensions/search-result",
		"extensions/simple-browser",
		"extensions/terminal-suggest",
		"extensions/tunnel-forwarding",
		"extensions/typescript-language-features"
	)

	foreach ($extensionDir in $extensionDirs) {
		Invoke-Step "npm ci --prefix $extensionDir --ignore-scripts"
	}
}

$nativeEngines = @(
	"extensions/hexcore-capstone",
	"extensions/hexcore-unicorn",
	"extensions/hexcore-llvm-mc"
)

foreach ($engineDir in $nativeEngines) {
	Invoke-Step "npm ci --prefix $engineDir --ignore-scripts"
	Invoke-Step "powershell -NoProfile -ExecutionPolicy Bypass -Command `"Set-Location '$engineDir'; node ..\\..\\scripts\\hexcore-native-install.js`""
}

$hexcoreExtensions = @(
	"extensions/hexcore-hexviewer",
	"extensions/hexcore-peanalyzer",
	"extensions/hexcore-hashcalc",
	"extensions/hexcore-strings",
	"extensions/hexcore-entropy",
	"extensions/hexcore-base64",
	"extensions/hexcore-filetype",
	"extensions/hexcore-common",
	"extensions/hexcore-ioc",
	"extensions/hexcore-minidump",
	"extensions/hexcore-yara",
	"extensions/hexcore-disassembler",
	"extensions/hexcore-debugger"
)

foreach ($extDir in $hexcoreExtensions) {
	Invoke-Step "npm ci --prefix $extDir"
	Invoke-Step "npm run compile --prefix $extDir"
}

Invoke-Step "npm run gulp vscode-win32-x64-min"

Write-Host "Build completed. Output should be in VSCode-win32-x64." -ForegroundColor Green
