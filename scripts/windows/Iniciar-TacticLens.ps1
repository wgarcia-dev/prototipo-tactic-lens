param([switch]$Detener,[switch]$NoAbrirNavegador,[switch]$SoloComprobar)
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Set-Location -LiteralPath $root
$python=Join-Path $root '.venv/Scripts/python.exe'
$stateDir=Join-Path $root '.local/run-local'
$stateFile=Join-Path $stateDir 'procesos.json'
function Get-TaskProcess($item) {
    $process=Get-CimInstance Win32_Process -Filter "ProcessId=$($item.Pid)" -ErrorAction SilentlyContinue
    if (-not $process) {return $null}
    $sameDate=([datetime]$process.CreationDate).ToUniversalTime().ToString('o') -eq [string]$item.Created
    if ($sameDate -and $process.CommandLine.Contains([string]$item.Marker)) {return $process}
    return $null
}
if ($Detener) {
    if (-not (Test-Path -LiteralPath $stateFile)) {Write-Host 'No hay procesos registrados por este lanzador.'; exit 0}
    $state=Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
    foreach ($item in $state) {
        $process=Get-TaskProcess $item
        if ($process) {
            # Only descendants of the exact process started by this launcher.
            $children=@(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($process.ProcessId)" -ErrorAction SilentlyContinue)
            foreach ($child in $children) {Stop-Process -Id $child.ProcessId -ErrorAction Stop}
            Stop-Process -Id $process.ProcessId -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $stateFile
    Write-Host 'Procesos propios detenidos. No se detuvo PostgreSQL ni otros servicios.'
    exit 0
}
if (-not (Test-Path -LiteralPath $python)) {throw 'Ejecute primero Preparar-NuevaPC.ps1'}
& $python -m scripts.portability check --model
if ($LASTEXITCODE -ne 0) {throw 'Base/modelo/configuracion no preparados; revise MIGRACION_NUEVA_PC.md. No se migra automaticamente.'}
if ($SoloComprobar) {Write-Host 'Configuracion y base local listas. No se iniciaron procesos.'; exit 0}
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
$tracked=New-Object System.Collections.Generic.List[object]
if (Test-Path -LiteralPath $stateFile) {
    foreach ($item in @(Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json)) {if(Get-TaskProcess $item){$tracked.Add($item)}}
}
function Start-LocalProcess($mode,$marker) {
    # DETACHED_PROCESS prevents an external PowerShell 5.1 host from waiting for
    # a hidden child's console after this script has finished.
    $result=& $python -m scripts.start_local_process $mode
    if ($LASTEXITCODE -ne 0) {throw 'No se pudo iniciar el proceso local'}
    $child=$result | ConvertFrom-Json
    $details=Get-CimInstance Win32_Process -Filter "ProcessId=$($child.pid)"
    if (-not $details) {throw 'El proceso local termino antes de quedar registrado; revise sus logs'}
    $tracked.Add([pscustomobject]@{Pid=$child.pid;Created=([datetime]$details.CreationDate).ToUniversalTime().ToString('o');Marker=$marker})
    ConvertTo-Json -InputObject @($tracked.ToArray()) | Set-Content -LiteralPath $stateFile -Encoding UTF8
}
function Get-Health($url) {try {return Invoke-RestMethod $url -TimeoutSec 3} catch {return $null}}
$health=Get-Health 'http://127.0.0.1:8000/api/health'
$backendListeners=@(Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue)
if ($health.contrato_ingesta -ne 'tacticlens.ingesta.v2') {
    if ($backendListeners.Count) {throw '8000 ocupado por un proceso no reconocido. No se detiene automaticamente.'}
    Start-LocalProcess 'backend' 'scripts.local_server'
    for ($attempt=0;$attempt -lt 30;$attempt++) {Start-Sleep -Milliseconds 500; $health=Get-Health 'http://127.0.0.1:8000/api/health'; if($health){break}}
    if ($health.contrato_ingesta -ne 'tacticlens.ingesta.v2') {throw 'Backend no listo; revise .local/run-local/backend.err.log'}
} elseif ($backendListeners | Where-Object {$_.LocalAddress -notin @('127.0.0.1','::1')}) {
    throw 'Existe un backend de demostracion LAN. Detengalo en su terminal y vuelva a iniciar en modo local; no se cambia su configuracion.'
}
$front=Get-Health 'http://127.0.0.1:5173/api/health'
if ($front.contrato_ingesta -ne 'tacticlens.ingesta.v2') {
    if (@(Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue).Count) {throw '5173 ocupado por otra aplicacion'}
    Get-Command node -ErrorAction Stop | Out-Null
    $vite=Join-Path $root 'frontend/node_modules/vite/bin/vite.js'
    if (-not (Test-Path -LiteralPath $vite)) {throw 'Ejecute Preparar-NuevaPC.ps1 para instalar React'}
    $env:VITE_API_PROXY_TARGET='http://127.0.0.1:8000'
    Start-LocalProcess 'frontend' $vite
    for ($attempt=0;$attempt -lt 30;$attempt++) {Start-Sleep -Milliseconds 500; $front=Get-Health 'http://127.0.0.1:5173/api/health'; if($front){break}}
    if ($front.contrato_ingesta -ne 'tacticlens.ingesta.v2') {throw 'Frontend no listo; revise .local/run-local/frontend.err.log'}
}
Write-Host 'TacticLens local: http://127.0.0.1:5173/; datos historicos disponibles sin Ubuntu.'
Write-Host 'Para detener solo estos procesos: .\scripts\windows\Iniciar-TacticLens.ps1 -Detener'
if (-not $NoAbrirNavegador) {Start-Process 'http://127.0.0.1:5173/'}
