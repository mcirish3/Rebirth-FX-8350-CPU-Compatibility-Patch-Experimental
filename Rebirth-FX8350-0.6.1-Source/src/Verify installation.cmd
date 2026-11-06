@echo off
setlocal
if "%~1"=="" ("%~dp0FxCompatInstaller.exe" verify) else ("%~dp0FxCompatInstaller.exe" verify "%~f1")
set "FXCOMPAT_EXIT=%ERRORLEVEL%"
pause
exit /b %FXCOMPAT_EXIT%
