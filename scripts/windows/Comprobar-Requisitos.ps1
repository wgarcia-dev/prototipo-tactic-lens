$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Set-Location $projectRoot
foreach ($tool in @('ssh.exe','scp.exe','node.exe','npm.cmd')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "Falta $tool" }
}
if (-not (Test-Path '.venv/Scripts/python.exe')) { throw 'Falta el entorno .venv del proyecto' }
if (-not (Test-Path '.env')) { throw 'Falta el .env privado de Windows' }
& ./.venv/Scripts/python.exe -m scripts.demo_status --database
if ($LASTEXITCODE -ne 0) { throw 'Revise PostgreSQL o las migraciones indicadas' }
Write-Host 'Requisitos comprobados. Conserve las claves existentes; no se enviaron correos.'
