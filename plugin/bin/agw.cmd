@echo off
setlocal
where py.exe >nul 2>nul
if not errorlevel 1 goto run_py
where python.exe >nul 2>nul
if not errorlevel 1 goto run_python
>&2 echo agentic-guardrails requires Python 3 but could not find py.exe or python.exe.
exit /b 9009

:run_py
py.exe -3 "%~dp0..\scripts\agw\agw.py" %*
exit /b %errorlevel%

:run_python
python.exe "%~dp0..\scripts\agw\agw.py" %*
exit /b %errorlevel%
