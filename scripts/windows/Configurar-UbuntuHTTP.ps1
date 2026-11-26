param(
    [Parameter(Mandatory=$true)][string]$UbuntuHost,
    [ValidatePattern('^[a-z_][a-z0-9_-]*$')][string]$Usuario = 'tacticadmin',
    [switch]$ExportadorPermanente,
    [switch]$ExportadorLive
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Set-Location $root
$state = Get-Content -LiteralPath '.local/demo-http/estado.json' -Raw | ConvertFrom-Json
if ($state.UbuntuIP -ne $UbuntuHost) { throw 'La IP no coincide con Iniciar-DemoHTTP.ps1; vuelva a iniciar la demostracion.' }
$health = Invoke-RestMethod 'http://127.0.0.1:8000/api/health' -TimeoutSec 5
if ($health.contrato_ingesta -ne 'tacticlens.ingesta.v2') { throw 'Inicie el backend compatible primero' }
$argumentos = @('-m', 'scripts.sync_ingest_key', '--host', $UbuntuHost, '--user', $Usuario, '--demo-url', $state.URL)
if ($ExportadorPermanente -and $ExportadorLive) { throw 'Seleccione un solo tipo de exportador.' }
if ($ExportadorPermanente) { $argumentos += '--permanente' }
if ($ExportadorLive) { $argumentos += '--live' }
& ./.venv/Scripts/python.exe @argumentos
if ($LASTEXITCODE -ne 0) { throw 'La instalacion o sincronizacion no termino; conserve la cola y revise el mensaje.' }
