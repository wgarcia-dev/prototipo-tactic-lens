$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$destination = Join-Path $projectRoot '.local/kit-cowrie'
$files = @('collector/exportar_eventos.py','collector/sqlite_sender.py','scripts/ubuntu/diagnostico.py',
    'scripts/ubuntu/configurar.sh','scripts/ubuntu/configurar-http.sh','scripts/ubuntu/verificar.sh','scripts/ubuntu/estado.sh','scripts/ubuntu/sincronizar.sh',
    'scripts/ubuntu/autorizar-windows.sh','scripts/ubuntu/probar-reconexion.sh')
foreach ($file in $files) {
    $target = Join-Path $destination $file
    New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
    $content = [IO.File]::ReadAllText((Join-Path $projectRoot $file)).Replace("`r`n","`n")
    [IO.File]::WriteAllText($target,$content,(New-Object Text.UTF8Encoding($false)))
}
Write-Host "Kit sin secretos creado en $destination"
Write-Host 'Copielo por SCP a Ubuntu. No transfiera .env, copias de PostgreSQL ni claves privadas.'
