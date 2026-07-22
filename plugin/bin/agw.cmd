@echo off
setlocal
where python >nul 2>nul
if not errorlevel 1 (
  call python -c "import sys; sys.exit(0 if sys.version_info.major == 3 else 1)" >nul 2>nul
  if not errorlevel 1 goto run_python
)
where py.exe >nul 2>nul
if not errorlevel 1 (
  py.exe -3 -c "import sys; sys.exit(0 if sys.version_info.major == 3 else 1)" >nul 2>nul
  if not errorlevel 1 goto run_py
)
>&2 echo Agentic Guardrails requires an accessible Python 3 interpreter. Tried python, then py.exe -3.
exit /b 9009

:run_py
py.exe -3 "%~dp0..\scripts\agw\agw.py" %*
exit /b %errorlevel%

:run_python
call python "%~dp0..\scripts\agw\agw.py" %*
exit /b %errorlevel%
