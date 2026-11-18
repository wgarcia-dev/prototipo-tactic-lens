param([switch]$Seguir)
$ErrorActionPreference = 'Stop'
do {
    try {
        $health = Invoke-RestMethod 'http://127.0.0.1:8000/api/health' -TimeoutSec 5
        [pscustomobject]@{Base=$health.database;Contrato=$health.contrato_ingesta;Eventos=$health.ingestion.eventos;
            UltimaIngesta=$health.ingestion.ultima_ingesta;UltimoLatido=$health.collector_last_seen} | Format-List
        Write-Host 'Los pendientes de SQLite se consultan en Ubuntu; un latido no confirma entrega de eventos.'
    } catch { Write-Warning 'Backend no disponible en loopback:8000' }
    if ($Seguir) { Start-Sleep -Seconds 5 }
} while ($Seguir)
