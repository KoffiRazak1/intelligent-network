@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo Environnement Python absent. Suis les instructions du README.md.
  pause
  exit /b 1
)

.venv\Scripts\python.exe backend\run.py
if errorlevel 1 (
  echo Le serveur s'est arrete avec une erreur.
  pause
  exit /b 1
)
