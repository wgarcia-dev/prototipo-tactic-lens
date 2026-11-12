param(
    [Parameter(Mandatory=$true)][string]$LocalIP,
    [Parameter(Mandatory=$true)][string]$UbuntuIP,
    [Parameter(Mandatory=$true)][int]$InterfaceIndex,
    [switch]$Quitar
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Set-Location $root
trap {
    $_.Exception.Message | Set-Content -LiteralPath (Join-Path $root '.local/demo-http/firewall-error.txt') -Encoding UTF8
    exit 1
}
$python = Join-Path $root '.venv/Scripts/python.exe'
foreach ($ip in @($LocalIP,$UbuntuIP)) {
    & $python -c 'import sys; from backend.ingest_transport import private_ipv4; private_ipv4(sys.argv[1])' $ip
    if ($LASTEXITCODE -ne 0) { throw 'Direcciones privadas no validas' }
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Windows requiere privilegios administrativos para modificar el firewall.' }
$name = 'TacticLens-DemoHTTP-Ubuntu'
. (Join-Path $PSScriptRoot 'Test-FirewallDemo.ps1')
if ($Quitar) {
    Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-Host 'Regla exclusiva de demostracion retirada.'
    exit 0
}
if (Test-FirewallDemo -LocalIP $LocalIP -UbuntuIP $UbuntuIP -InterfaceIndex $InterfaceIndex) {
    'ok' | Set-Content -LiteralPath (Join-Path $root '.local/demo-http/firewall-ok.txt') -Encoding ASCII
    Write-Host 'La regla restringida y el perfil ya son correctos; no se modifica el firewall.'
    exit 0
}
$address = Get-NetIPAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 | Where-Object IPAddress -EQ $LocalIP
if (-not $address -or $LocalIP -eq $UbuntuIP) { throw 'La IP local no pertenece a la interfaz seleccionada' }
$interface = (Get-NetAdapter -InterfaceIndex $InterfaceIndex).Name
$connection = Get-NetConnectionProfile -InterfaceIndex $InterfaceIndex
$profile = switch ([int]$connection.NetworkCategory) { 0 { 'Public' } 1 { 'Private' } 2 { 'Domain' } default { throw 'Perfil de red no reconocido' } }
$current = Get-NetFirewallProfile -Name $profile
if (-not (Test-Path -LiteralPath (Join-Path $root '.local/demo-http/firewall-previo.json'))) {
    $current | Select-Object Name,Enabled,DefaultInboundAction | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root '.local/demo-http/firewall-previo.json') -Encoding UTF8
}
# The host may have its firewall disabled. An allow rule alone would not restrict
# access. Enable only the profile in use by this interface, preserving others.
Set-NetFirewallProfile -Name $profile -Enabled True -DefaultInboundAction Block
Write-Host "Firewall del perfil $profile activo con entrada bloqueada por defecto."
# Replace only our own rule when the hotspot changes; never widen old rules.
Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -Name $name -DisplayName 'TacticLens: HTTP demo solo Ubuntu' -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort 8000 -LocalAddress $LocalIP -RemoteAddress $UbuntuIP -InterfaceAlias $interface `
    -Profile Any -EdgeTraversalPolicy Block | Out-Null
$rule = Get-NetFirewallRule -Name $name
$filter = $rule | Get-NetFirewallAddressFilter
if ($filter.RemoteAddress -ne $UbuntuIP -or $filter.LocalAddress -ne $LocalIP) { throw 'La regla no tiene el alcance solicitado' }
Write-Host "Firewall preparado: $UbuntuIP -> ${LocalIP}:8000, interfaz $interface. No se abrieron otros puertos."
'ok' | Set-Content -LiteralPath (Join-Path $root '.local/demo-http/firewall-ok.txt') -Encoding ASCII
