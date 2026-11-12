param([Parameter(Mandatory=$true)][string]$UbuntuHost)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Set-Location $root
$state = Get-Content -LiteralPath '.local/demo-http/estado.json' -Raw | ConvertFrom-Json
if ($state.UbuntuIP -ne $UbuntuHost) { throw 'La IP no coincide con Iniciar-DemoHTTP.ps1; vuelva a iniciar la demostracion.' }
$health = Invoke-RestMethod 'http://127.0.0.1:8000/api/health' -TimeoutSec 5
if ($health.contrato_ingesta -ne 'tacticlens.ingesta.v2') { throw 'Inicie el backend compatible primero' }
& ./.venv/Scripts/python.exe -m scripts.sync_ingest_key --host $UbuntuHost --demo-url $state.URL
if ($LASTEXITCODE -ne 0) { throw 'La instalacion o sincronizacion no termino; conserve la cola y revise el mensaje.' }
