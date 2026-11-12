$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
try { $health = Invoke-RestMethod 'http://127.0.0.1:8000/api/health' -TimeoutSec 3 } catch { $health = $null }
if ($health) {
    if ($health.contrato_ingesta -ne 'tacticlens.ingesta.v2') { throw 'Hay un backend anterior en 8000. Detengalo con Ctrl+C y ejecute este script otra vez.' }
    Write-Host 'El backend compatible ya esta activo. No se inicia otra instancia.'
    exit 0
}
& ./.venv/Scripts/python.exe -m scripts.demo_status --database
if ($LASTEXITCODE -ne 0) { throw 'Compruebe PostgreSQL y aplique las migraciones despues de respaldar.' }
& ./.venv/Scripts/python.exe -m uvicorn backend.api:app --host 127.0.0.1 --port 8000
