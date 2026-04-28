@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
  py -m unicode_guard.gui
  goto :end
)

where python >nul 2>nul
if %errorlevel%==0 (
  python -m unicode_guard.gui
  goto :end
)

if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" (
  "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" -m unicode_guard.gui
  goto :end
)

echo Python was not found. Please install Python 3.10+ or run from Codex bundled Python.
pause

:end
endlocal
