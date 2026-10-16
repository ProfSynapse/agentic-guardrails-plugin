@echo off
setlocal DisableDelayedExpansion
rem Keep shell operators inside cmd.exe: Codex may launch hooks in PowerShell 5.1.
where py.exe >nul 2>nul
if not errorlevel 1 (
  py.exe -3 -c "import sys; sys.exit(0 if sys.version_info.major == 3 else 1)" >nul 2>nul
  if not errorlevel 1 goto run_py
)
where python >nul 2>nul
if not errorlevel 1 (
  call python -c "import sys; sys.exit(0 if sys.version_info.major == 3 else 1)" >nul 2>nul
  if not errorlevel 1 goto run_python
)
>&2 echo Agentic Guardrails requires Python 3. Tried py.exe -3, then python.
if /i "%~1"=="pretooluse" (
  echo {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Agentic Guardrails requires Python 3; the operation is blocked until its hook launcher is repaired."}}
  exit /b 0
)
exit /b 9009

:run_py
py.exe -3 "%~dp0_dispatch.py" %1
exit /b %errorlevel%

:run_python
call python "%~dp0_dispatch.py" %1
exit /b %errorlevel%
