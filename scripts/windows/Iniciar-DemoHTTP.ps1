param([Parameter(Mandatory=$true)][string]$UbuntuHost)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Set-Location $root
$python = Join-Path $root '.venv/Scripts/python.exe'
& $python -c 'import sys; from backend.ingest_transport import private_ipv4; private_ipv4(sys.argv[1])' $UbuntuHost
if ($LASTEXITCODE -ne 0) { throw 'Indique la IPv4 privada actual de Ubuntu' }
$route = @(Find-NetRoute -RemoteIPAddress $UbuntuHost)
$source = $route | Where-Object IPAddress | Select-Object -First 1
$hop = $route | Where-Object DestinationPrefix | Select-Object -First 1
if (-not $source -or $hop.NextHop -ne '0.0.0.0') { throw 'Ubuntu debe estar en la red local directa; revise la IP y la conexion Wi-Fi/hotspot.' }
$localIP = $source.IPAddress
$interfaceIndex = $source.InterfaceIndex
& $python -m scripts.demo_prepare --check-environment
if ($LASTEXITCODE -ne 0) { throw 'Esta modalidad requiere AUTH_ENV=development' }
& $python -m scripts.demo_status --database
if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL o esquema no disponibles' }
& $python -m scripts.serve_demo --local-ip $localIP --ubuntu-ip $UbuntuHost --check-ports
if ($LASTEXITCODE -ne 0) {
    throw 'El puerto 8000 esta ocupado. Detenga con Ctrl+C el backend anterior antes de iniciar esta modalidad.'
}
# Only the dedicated ingestion tunnel is eligible for automatic termination.
$tunnels = Get-CimInstance Win32_Process -Filter "Name='ssh.exe'" | Where-Object {
    $_.CommandLine -match '(?:-R\s*|\s)127\.0\.0\.1:18765:127\.0\.0\.1:8000' -and $_.CommandLine -match '\s-N(?:\s|$)'
}
foreach ($tunnel in $tunnels) { Stop-Process -Id $tunnel.ProcessId -ErrorAction Stop }
Write-Host 'No se utiliza tunel. Cierre con Ctrl+C cualquier ventana antigua Abrir-Tunel o sincronizacion de clave que siga esperando; conserve sus sesiones SSH administrativas.'
$private = Join-Path $root '.local/demo-http'
New-Item -ItemType Directory -Force -Path $private | Out-Null
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
# Secrets are exclusively for this demo and never overwrite the normal .env key.
& icacls.exe $private /inheritance:r /grant:r "*${sid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'No se pudieron proteger los secretos locales' }
$keyPath = Join-Path $private 'ingest.key'
if (-not (Test-Path -LiteralPath $keyPath)) {
    & $python -m scripts.demo_prepare --create-key $keyPath
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo crear la clave exclusiva' }
}
& icacls.exe $keyPath /inheritance:r /grant:r "*${sid}:F" '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'No se pudo proteger la clave' }
$firewall = Join-Path $PSScriptRoot 'Configurar-FirewallDemo.ps1'
. (Join-Path $PSScriptRoot 'Test-FirewallDemo.ps1')
foreach ($name in @('firewall-error.txt','firewall-ok.txt')) {
    $marker = Join-Path $private $name
    if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker }
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (Test-FirewallDemo -LocalIP $localIP -UbuntuIP $UbuntuHost -InterfaceIndex $interfaceIndex) {
    Write-Host 'Regla de firewall verificada y reutilizada. No se solicita UAC.'
} elseif ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    & $firewall -LocalIP $localIP -UbuntuIP $UbuntuHost -InterfaceIndex $interfaceIndex
} else {
    Write-Host 'Windows solicitara elevacion UAC unicamente para la regla restringida del firewall.'
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$firewall`" -LocalIP $localIP -UbuntuIP $UbuntuHost -InterfaceIndex $interfaceIndex"
    $elevated = Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList $arguments -Wait -PassThru
    if (-not (Test-Path -LiteralPath (Join-Path $private 'firewall-ok.txt'))) {
        if (Test-Path -LiteralPath (Join-Path $private 'firewall-error.txt')) { Get-Content -LiteralPath (Join-Path $private 'firewall-error.txt') | Write-Warning }
        throw 'Windows no confirmo la regla de firewall. No se expone el backend.'
    }
}
if (-not (Test-FirewallDemo -LocalIP $localIP -UbuntuIP $UbuntuHost -InterfaceIndex $interfaceIndex)) { throw 'La regla efectiva no coincide con el alcance solicitado; backend cerrado.' }
$state = @{WindowsIP=$localIP; UbuntuIP=$UbuntuHost; InterfaceIndex=$interfaceIndex; URL="http://${localIP}:8000/api/ingesta/eventos"}
$state | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $private 'estado.json') -Encoding UTF8
Write-Host "API para Ubuntu: $($state.URL)"
Write-Host 'Frontend y consultas locales: http://127.0.0.1:5173; salud: http://127.0.0.1:8000/api/health'
Write-Host 'Ctrl+C detiene el backend. En otra terminal ejecute Configurar-UbuntuHTTP.ps1.'
& $python -m scripts.serve_demo --local-ip $localIP --ubuntu-ip $UbuntuHost
if ($LASTEXITCODE -ne 0) { throw 'Backend de demostracion detenido con error' }
