$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '../../frontend')).Path
if (-not (Test-Path 'node_modules')) { throw 'Instale las dependencias existentes con npm.cmd ci antes de iniciar.' }
# Process-only override wins over stale Vite .env files; no credentials here.
$env:VITE_API_PROXY_TARGET = 'http://127.0.0.1:8000'
try { $health = Invoke-RestMethod 'http://127.0.0.1:5173/api/health' -TimeoutSec 3 } catch { $health = $null }
if ($health.contrato_ingesta -eq 'tacticlens.ingesta.v2') { Write-Host 'Frontend y proxy compatibles ya activos en 5173.'; exit 0 }
& npm.cmd run dev -- --strictPort
