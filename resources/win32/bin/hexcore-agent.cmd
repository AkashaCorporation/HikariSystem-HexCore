@echo off
setlocal
set VSCODE_DEV=
set ELECTRON_RUN_AS_NODE=1
set "HEXCORE_AGENT_EXE=%~dp0..\@@NAME@@.exe"
if defined HEXCORE_AGENT_EXECUTABLE set "HEXCORE_AGENT_EXE=%HEXCORE_AGENT_EXECUTABLE%"

set "HEXCORE_AGENT_SCRIPT=%~dp0..\resources\app\extensions\hexcore-disassembler\bin\hexcore-agent.cjs"
if not exist "%HEXCORE_AGENT_SCRIPT%" (
	for /d %%D in ("%~dp0..\*") do (
		if exist "%%~fD\resources\app\extensions\hexcore-disassembler\bin\hexcore-agent.cjs" set "HEXCORE_AGENT_SCRIPT=%%~fD\resources\app\extensions\hexcore-disassembler\bin\hexcore-agent.cjs"
	)
)

if not exist "%HEXCORE_AGENT_SCRIPT%" (
	echo {"ok":false,"error":{"code":"agent-cli-missing","message":"Packaged HexCore Agent Bridge CLI was not found."}} 1>&2
	exit /b 3
)

if not exist "%HEXCORE_AGENT_EXE%" (
	echo {"ok":false,"error":{"code":"agent-runtime-missing","message":"HexCore executable for Agent Bridge CLI was not found."}} 1>&2
	exit /b 3
)

"%HEXCORE_AGENT_EXE%" "%HEXCORE_AGENT_SCRIPT%" %*
set "HEXCORE_AGENT_EXIT=%ERRORLEVEL%"
endlocal & exit /b %HEXCORE_AGENT_EXIT%
