@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS_EXE=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS_EXE%" (
  echo ERROR: Windows PowerShell 5.1 was not found.
  exit /b 1
)
if not exist "%~dp0scripts\KIRSidRepair.ps1" (
  echo ERROR: Missing scripts\KIRSidRepair.ps1. Extract the full ZIP first.
  exit /b 1
)
"%PS_EXE%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\KIRSidRepair.ps1" %*
set "RESULT=%ERRORLEVEL%"
endlocal & exit /b %RESULT%
