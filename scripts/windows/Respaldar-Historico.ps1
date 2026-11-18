param([Parameter(Mandatory=$true)][string]$Destino, [string]$PgBin='C:/Program Files/PostgreSQL/18/bin')
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Set-Location $root
if (-not (Test-Path .env)) { throw 'Ejecute este script en la computadora anterior con su .env original.' }
Write-Host 'Detenga primero FastAPI y el exportador: el manifiesto debe corresponder al mismo estado del respaldo.'
& ./.venv/Scripts/python.exe -m scripts.historical_database backup --config .env --dump $Destino --bin $PgBin
if ($LASTEXITCODE -ne 0) { throw 'Respaldo incompleto; no transferir todavía.' }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
foreach ($file in @($Destino, "$Destino.json", "$Destino.auth.env")) {
    & icacls.exe $file /inheritance:r /grant:r "*${sid}:F" '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo restringir el archivo privado.' }
}
Write-Host 'Transfiera los tres archivos por USB privado cifrado. Nunca GitHub ni el chat.'
