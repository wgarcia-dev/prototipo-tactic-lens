$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../scripts/windows/Test-FirewallDemo.ps1')
$script:localIP = '192.168.0.111'
$script:remoteIP = '192.168.0.110'
$script:port = '8000'
$script:interface = 'Ethernet'
$script:enabled = 1
function Get-NetFirewallRule { [pscustomobject]@{Enabled=1;Direction=1;Action=2;EdgeTraversalPolicy=0;Profile=0} }
function Get-NetFirewallAddressFilter { process { [pscustomobject]@{LocalAddress=$script:localIP;RemoteAddress=$script:remoteIP} } }
function Get-NetFirewallPortFilter { process { [pscustomobject]@{LocalPort=$script:port;Protocol='TCP'} } }
function Get-NetFirewallInterfaceFilter { process { [pscustomobject]@{InterfaceAlias=$script:interface} } }
function Get-NetAdapter { [pscustomobject]@{Name='Ethernet'} }
function Get-NetConnectionProfile { [pscustomobject]@{NetworkCategory=0} }
function Get-NetFirewallProfile { [pscustomobject]@{Enabled=$script:enabled;DefaultInboundAction=4} }
function Start-Process { throw 'El comprobador nunca debe pedir UAC' }
function Check([bool]$expected,[string]$case) {
    $actual = Test-FirewallDemo -LocalIP 192.168.0.111 -UbuntuIP 192.168.0.110 -InterfaceIndex 19
    if ($actual -ne $expected) { throw "Fallo: $case" }
    Write-Host "OK: $case"
}
Check $true 'Regla existente correcta, propiedades de tipo string: sin UAC'
$script:remoteIP = @('192.168.0.110','192.168.0.112'); Check $false 'Rechaza fuentes adicionales'
$script:remoteIP = 'Any'; Check $false 'Rechaza origen general'
$script:remoteIP = '192.168.0.112'; Check $false 'Detecta cambio de Ubuntu'
$script:remoteIP = '192.168.0.110'; $script:localIP = '192.168.56.1'; Check $false 'Detecta IP local incorrecta'
$script:localIP = '192.168.0.111'; $script:port = @('8000','8001'); Check $false 'Rechaza puertos adicionales'
$script:port = '8000'; $script:interface = 'Wi-Fi'; Check $false 'Detecta cambio de interfaz'
$script:interface = 'Ethernet'; $script:enabled = 0; Check $false 'No acepta firewall desactivado'
$script:enabled = 1; $script:remoteIP = @('192.168.0.110'); Check $true 'Admite propiedades como array de un elemento'
Write-Host '9 comprobaciones del firewall correctas. No se modificaron reglas ni se elevo PowerShell.'
