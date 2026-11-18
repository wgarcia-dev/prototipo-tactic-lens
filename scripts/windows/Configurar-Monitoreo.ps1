param([string]$UbuntuHost='192.168.0.100',[switch]$SoloComprobar)
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Set-Location $root
$state=Get-Content -LiteralPath '.local/demo-http/estado.json' -Raw | ConvertFrom-Json
if ($state.UbuntuIP -ne $UbuntuHost -or $UbuntuHost -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { throw 'Inicie el backend con la IP actual de Ubuntu primero.' }
if ($state.URL -notmatch '^http://\d{1,3}(\.\d{1,3}){3}:8000/api/ingesta/eventos$') { throw 'URL de demostracion no valida' }
$source=(Resolve-Path -LiteralPath 'scripts/ubuntu/configurar_monitoreo.py').Path
$remoteName='.tacticlens-monitoreo-'+[Guid]::NewGuid().ToString('N')+'.py'
$target='tacticadmin@'+$UbuntuHost
$options=@('-o','StrictHostKeyChecking=yes','-o','HostKeyAlias=tacticlens-cowrie','-o','ConnectTimeout=8')
$copy=$options+@($source,($target+':./'+$remoteName))
$command='cleanup() { rm -f -- ./'+$remoteName+'; }; trap cleanup EXIT; sudo python3 ./'+$remoteName+' --url '+$state.URL
$remote=@('-tt')+$options+@($target,$command)
if($SoloComprobar){[pscustomobject]@{SCP=$copy;SSH=$remote}|ConvertTo-Json -Depth 4;exit 0}
$health=Invoke-RestMethod 'http://127.0.0.1:8000/api/health' -TimeoutSec 5
if($health.contrato_ingesta -ne 'tacticlens.ingesta.v2'){throw 'Inicie el backend compatible primero'}
Write-Host 'Se necesitan sus contrasenas solo en esta terminal: SCP, SSH y sudo. No se reinstala el exportador.'
& scp.exe @copy
if($LASTEXITCODE -ne 0){throw 'No se pudo copiar el auxiliar; no se modifico el temporizador'}
& ssh.exe @remote
if($LASTEXITCODE -ne 0){throw 'Revise el resultado del ajuste; la cola no se elimina'}
Write-Host 'Temporizador configurado. El transporte de eventos sigue siendo HTTP directo.'
