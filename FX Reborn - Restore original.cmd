@echo off
rem Puts the original game exe back.
rem Game folders can need administrator rights, so ask for them first.
set "FXR_SELF=%~f0"
net session >nul 2>&1
if not errorlevel 1 goto elevated
powershell -NoProfile -Command "Start-Process -FilePath $env:FXR_SELF -Verb RunAs" 2>nul
if errorlevel 1 echo Could not get administrator rights. & pause
exit /b
:elevated
cd /d "%~dp0"
if exist "python\python.exe" goto bundled
py -3.13 -c "" >nul 2>&1
if errorlevel 1 goto nopython
py -3.13 fxreborn.py restore %*
goto done
:bundled
"python\python.exe" fxreborn.py restore %*
goto done
:nopython
echo FX Reborn needs Python 3.13. Use the player download from Nexus Mods or GitHub
echo Releases (it includes Python), or install Python 3.13 from python.org.
:done
pause
