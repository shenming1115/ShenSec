@echo off
setlocal
cd /d "%~dp0"
where uv >nul 2>&1
if errorlevel 1 (
  echo Install uv first: https://docs.astral.sh/uv/getting-started/installation/
  pause
  exit /b 1
)
if /i "%~1"=="demo" (
  call uv run --locked --extra gui shensec demo --identities --gui
) else (
  call uv run --locked --extra gui shensec gui
)
if errorlevel 1 pause
