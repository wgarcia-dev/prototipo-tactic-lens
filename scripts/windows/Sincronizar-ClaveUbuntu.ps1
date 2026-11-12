param([ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]*$')][string]$UbuntuHost = '192.168.0.110')
$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
& ./scripts/windows/Configurar-UbuntuHTTP.ps1 -UbuntuHost $UbuntuHost
if ($LASTEXITCODE -ne 0) { throw 'Clave no alineada. No se han dado por enviados los pendientes.' }
