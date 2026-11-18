param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]*$')][string]$UbuntuHost,
    [ValidatePattern('^[a-z_][a-z0-9_-]*$')][string]$Usuario = 'tacticadmin',
    [string]$IdentityFile,
    [switch]$Reconectar
)
$ErrorActionPreference = 'Stop'
$PuertoRemoto = 18765
if (-not $UbuntuHost) { $UbuntuHost = Read-Host 'IP o nombre actual de Ubuntu (ejemplo: 192.168.0.110)' }
if ($UbuntuHost -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*$') { throw 'Direccion no valida' }
$health = Invoke-RestMethod 'http://127.0.0.1:8000/api/health' -TimeoutSec 5
if ($health.database -ne 'connected' -or $health.contrato_ingesta -ne 'tacticlens.ingesta.v2') { throw 'Inicie primero el backend compatible en loopback.' }
if (-not (Test-NetConnection $UbuntuHost -Port 22 -InformationLevel Quiet -WarningAction SilentlyContinue)) { throw 'No se alcanza SSH/22. Revise la IP, el hotspot y UFW.' }
$sshArgs = @('-N','-T','-o','ExitOnForwardFailure=yes','-o','ConnectTimeout=8','-o','ServerAliveInterval=15',
    '-o','ServerAliveCountMax=3','-o','StrictHostKeyChecking=ask','-o','HostKeyAlias=tacticlens-cowrie','-R',"127.0.0.1:${PuertoRemoto}:127.0.0.1:8000")
if ($IdentityFile) { $sshArgs += @('-i',(Resolve-Path -LiteralPath $IdentityFile).Path) }
$sshArgs += "$Usuario@$UbuntuHost"
Write-Host "Destino del exportador: http://127.0.0.1:$PuertoRemoto/api/ingesta/eventos"
Write-Host 'Verifique la huella SSH por un canal confiable. Mantenga esta ventana abierta; Ctrl+C cierra el tunel.'
Write-Host 'En Ubuntu ejecute verificar.sh: debe confirmar que el puerto remoto escucha SOLO en 127.0.0.1.'
do {
    & ssh.exe @sshArgs
    if (-not $Reconectar) { break }
    Write-Host 'SSH termino. Reintentando en 5 segundos. Si cambio la IP de Ubuntu, cierre con Ctrl+C y vuelva a indicarla.'
    Start-Sleep -Seconds 5
} while ($true)
