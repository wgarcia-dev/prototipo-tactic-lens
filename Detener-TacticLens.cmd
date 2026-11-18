@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\Detener-TacticLens.ps1"
if errorlevel 1 (
  echo Revise el mensaje anterior antes de volver a intentar.
  pause
  exit /b 1
)
