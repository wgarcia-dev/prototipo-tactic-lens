param([string]$UbuntuHost='192.168.0.103',[switch]$SoloComprobar)
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Set-Location $root
$state=Get-Content -LiteralPath '.local/demo-http/estado.json' -Raw | ConvertFrom-Json
if($state.UbuntuIP -ne $UbuntuHost -or $UbuntuHost -notmatch '^\d{1,3}(\.\d{1,3}){3}$'){throw 'Inicie Iniciar-DemoHTTP.ps1 con la IP actual de Ubuntu primero.'}
if($state.URL -notmatch '^http://\d{1,3}(\.\d{1,3}){3}:8000/api/ingesta/eventos$'){throw 'URL local no valida'}
$kit=Join-Path $root '.local/realtime-kit'
New-Item -ItemType Directory -Force -Path $kit | Out-Null
Copy-Item -LiteralPath 'collector/event_watch.py' -Destination (Join-Path $kit 'event_watch.py')
Copy-Item -LiteralPath 'scripts/ubuntu/activar_eventos.py' -Destination (Join-Path $kit 'activar_eventos.py')
Copy-Item -LiteralPath 'collector/event_status.py' -Destination (Join-Path $kit 'event_status.py')
foreach($name in @('estado.sh','verificar.sh','sincronizar.sh','probar-reconexion.sh')){
    $text=[IO.File]::ReadAllText((Join-Path $root ('scripts/ubuntu/'+$name))).Replace("`r`n","`n")
    [IO.File]::WriteAllText((Join-Path $kit $name),$text,(New-Object Text.UTF8Encoding($false)))
}
function Get-NormalizedHash([string]$Path){
    $text=[IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path).Path).Replace("`r`n","`n")
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)))).Replace('-','').ToLowerInvariant()}
    finally{$sha.Dispose()}
}
$exporter=Get-NormalizedHash 'collector/exportar_eventos.py'
$sender=Get-NormalizedHash 'collector/sqlite_sender.py'
$remote='.tacticlens-eventos-'+[guid]::NewGuid().ToString('N')
$target='tacticadmin@'+$UbuntuHost
$options=@('-o','StrictHostKeyChecking=yes','-o','HostKeyAlias=tacticlens-cowrie','-o','ConnectTimeout=8')
$copy=@('-r')+$options+@($kit,($target+':./'+$remote))
$files=@('activar_eventos.py','event_watch.py','event_status.py','estado.sh','verificar.sh','sincronizar.sh','probar-reconexion.sh') | ForEach-Object {'./'+$remote+'/'+$_}
$command='sudo python3 ./'+$remote+'/activar_eventos.py --url '+$state.URL+' --exporter-sha '+$exporter+' --sender-sha '+$sender+'; result=$?; rm -f -- '+($files -join ' ')+'; rmdir -- ./'+$remote+'; exit $result'
$ssh=@('-tt')+$options+@($target,$command)
if($SoloComprobar){[pscustomobject]@{SCP=$copy;SSH=$ssh}|ConvertTo-Json -Depth 4;exit 0}
$health=Invoke-RestMethod 'http://127.0.0.1:8000/api/health' -TimeoutSec 5
if($health.contrato_ingesta -ne 'tacticlens.ingesta.v2'){throw 'Backend existente no disponible'}
Write-Host 'Solo SCP/SSH administrativo. Contrasenas SSH y sudo unicamente en esta terminal; no se copian claves.'
& scp.exe @copy
if($LASTEXITCODE -ne 0){throw 'No se transfirio el auxiliar; servicios intactos'}
& ssh.exe @ssh
if($LASTEXITCODE -ne 0){throw 'Activacion no confirmada. Revise salida; no borre la cola'}
Write-Host 'Vigilancia inotify activa en el mismo servicio. Transporte HTTP directo; React usa WebSocket.'
