@echo off
setlocal
node "%~dp0..\extensions\hexcore-disassembler\bin\hexcore-agent.cjs" %*
set "HEXCORE_AGENT_EXIT=%ERRORLEVEL%"
endlocal & exit /b %HEXCORE_AGENT_EXIT%
