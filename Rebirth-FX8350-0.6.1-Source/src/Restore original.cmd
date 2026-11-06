@echo off
setlocal
if "%~1"=="" ("%~dp0FxCompatInstaller.exe" restore) else ("%~dp0FxCompatInstaller.exe" restore "%~f1")
set "FXCOMPAT_EXIT=%ERRORLEVEL%"
pause
exit /b %FXCOMPAT_EXIT%
