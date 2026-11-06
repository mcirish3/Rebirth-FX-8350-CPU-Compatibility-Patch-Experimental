@echo off
setlocal
if "%~1"=="" ("%~dp0FxCompatInstaller.exe" diagnose) else ("%~dp0FxCompatInstaller.exe" diagnose "%~f1")
set "FXCOMPAT_EXIT=%ERRORLEVEL%"
pause
exit /b %FXCOMPAT_EXIT%
