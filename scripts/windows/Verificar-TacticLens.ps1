param()
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Set-Location -LiteralPath $root
$python=Join-Path $root '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $python)) {throw 'Ejecute primero Preparar-NuevaPC.ps1'}
& $python -m scripts.verify_local
if ($LASTEXITCODE -ne 0) {throw 'Verificacion no completada. No se modificaron datos ni se llamo a DeepSeek.'}
Write-Host 'Entorno local verificado sin Ubuntu, sin correo y sin llamadas de pago.'
Write-Host 'Inicie sesion en http://127.0.0.1:5173 con su cuenta y MFA para la comprobacion visual autenticada.'
