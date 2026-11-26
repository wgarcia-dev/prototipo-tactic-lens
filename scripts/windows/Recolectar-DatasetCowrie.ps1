[CmdletBinding()]
param(
    [string]$UbuntuHost = '192.168.56.101',
    [string[]]$Escenarios = @(),
    [ValidateRange(1,10)][int]$Repeticiones = 1,
    [switch]$SoloMostrar
)
$ErrorActionPreference = 'Stop'
$runner = Join-Path $PSScriptRoot 'Probar-Cowrie.ps1'
$summary = @()
foreach ($entry in @(@{ Mode='cowrie_shell'; Port=2222 }, @{ Mode='cowrie_proxy'; Port=2223 }, @{ Mode='cowrie_llm'; Port=2224 })) {
    Write-Host ("Modalidad {0}, puerto {1}" -f $entry.Mode,$entry.Port)
    if (-not $SoloMostrar) {
        $client = [System.Net.Sockets.TcpClient]::new()
        $ready = $false
        try {
            $connect = $client.ConnectAsync($UbuntuHost, $entry.Port)
            if ($connect.Wait(3000) -and $client.Connected) {
                $stream = $client.GetStream()
                $stream.ReadTimeout = 3000
                $bytes = [byte[]]::new(128)
                $count = $stream.Read($bytes, 0, $bytes.Length)
                $ready = $count -gt 0 -and [Text.Encoding]::ASCII.GetString($bytes, 0, $count).StartsWith('SSH-')
            }
        } catch {
            $ready = $false
        } finally {
            $client.Dispose()
        }
        if (-not $ready) {
            Write-Warning ("{0}:{1} no ofrece SSH; se omiten sus escenarios." -f $UbuntuHost,$entry.Port)
            $summary += [pscustomobject]@{ modalidad=$entry.Mode; puerto=$entry.Port; estado='omitida_puerto_no_disponible' }
            continue
        }
    }
    & $runner -UbuntuHost $UbuntuHost -Port $entry.Port -Modalidad $entry.Mode -Escenarios $Escenarios -Repeticiones $Repeticiones -SoloMostrar:$SoloMostrar
    $summary += [pscustomobject]@{ modalidad=$entry.Mode; puerto=$entry.Port; estado=$(if ($SoloMostrar) { 'mostrada' } else { 'ejecucion_intentada_revisar_manifiesto' }) }
}
if (-not $SoloMostrar) { $summary | Format-Table -AutoSize }
