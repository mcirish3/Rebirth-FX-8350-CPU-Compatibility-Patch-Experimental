@echo off
setlocal
if "%~1"=="" ("%~dp0FxCompatInstaller.exe" install) else ("%~dp0FxCompatInstaller.exe" install "%~f1")
set "FXCOMPAT_EXIT=%ERRORLEVEL%"
pause
exit /b %FXCOMPAT_EXIT%
