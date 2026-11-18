@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\Iniciar-TacticLens.ps1" -NoAbrirNavegador
if errorlevel 1 (
  echo No se pudo iniciar TacticLens. Revise el mensaje anterior.
  pause
  exit /b 1
)
start "" "http://127.0.0.1:5173"
