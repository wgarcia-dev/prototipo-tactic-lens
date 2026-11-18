param([switch]$SoloComprobar,[switch]$PrepararModelo,[string]$PgBinDirectory)
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Set-Location -LiteralPath $root
$problems=New-Object System.Collections.Generic.List[string]
foreach ($name in @('git','python','node','npm.cmd')) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {$problems.Add("Falta $name en PATH")}
}
if ($PgBinDirectory) {$env:PG_BIN_DIRECTORY=$PgBinDirectory}
$pgCandidates=@($env:PG_BIN_DIRECTORY,(Join-Path $env:ProgramFiles 'PostgreSQL/18/bin')) | Where-Object {$_}
$pgBin=$pgCandidates | Where-Object {(Test-Path -LiteralPath (Join-Path $_ 'pg_dump.exe')) -and (Test-Path -LiteralPath (Join-Path $_ 'pg_restore.exe'))} | Select-Object -First 1
if (-not $pgBin) {$problems.Add('Faltan clientes PostgreSQL 18; instale PostgreSQL o indique -PgBinDirectory')}
else {
    $env:PG_BIN_DIRECTORY=$pgBin
    foreach ($tool in @('pg_dump.exe','pg_restore.exe')) {
        $version=& (Join-Path $pgBin $tool) --version
        if ($LASTEXITCODE -ne 0 -or $version -notmatch '18\.') {$problems.Add("$tool debe ser version 18")}
        else {Write-Host $version}
    }
}
if ($problems.Count) {throw ($problems -join [Environment]::NewLine)}
& python -c "import sys; assert (3,10)<=sys.version_info[:2]<(3,14), 'Use Python x64 3.10-3.13'; assert sys.maxsize>2**32, 'Python debe ser x64'; print('Python',sys.version.split()[0])"
if ($LASTEXITCODE -ne 0) {throw 'Python no compatible'}
& node -e "const [a,b]=process.versions.node.split('.').map(Number); if(a<22||(a===22&&b<13))process.exit(1); console.log('Node',process.versions.node)"
if ($LASTEXITCODE -ne 0) {throw 'Se requiere Node 22.13 o posterior (24 LTS comprobado)'}
$python=Join-Path $root '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    if ($SoloComprobar) {throw 'Falta .venv; ejecute sin -SoloComprobar'}
    & python -m venv .venv
    if ($LASTEXITCODE -ne 0) {throw 'No se pudo crear .venv'}
}
& $python -m scripts.environment_check
$pythonReady=$LASTEXITCODE -eq 0
if ($SoloComprobar -and -not $pythonReady) {throw 'Faltan dependencias del lock; ejecute sin -SoloComprobar'}
$nodeStamp=Join-Path $root 'frontend/node_modules/.tacticlens-lock.sha256'
$lockHash=(Get-FileHash -LiteralPath frontend/package-lock.json -Algorithm SHA256).Hash
$installedHash=if(Test-Path -LiteralPath $nodeStamp){(Get-Content -LiteralPath $nodeStamp -Raw).Trim()}else{''}
Push-Location frontend
try {& node -e "const fs=require('fs');const l=JSON.parse(fs.readFileSync('package-lock.json'));try{for(const n of Object.keys({...l.packages[''].dependencies,...l.packages[''].devDependencies})){if(JSON.parse(fs.readFileSync('node_modules/'+n+'/package.json')).version!==l.packages['node_modules/'+n].version)process.exit(1)}}catch(e){process.exit(1)}"; $nodeReady=$LASTEXITCODE -eq 0} finally {Pop-Location}
if ($SoloComprobar -and (-not $nodeReady -or ($installedHash -and $installedHash -ne $lockHash))) {throw 'Faltan dependencias React del lock; ejecute sin -SoloComprobar'}
if (-not $SoloComprobar) {
    if (-not $pythonReady) {
    & $python -m pip install -r requirements-portable.lock.txt
    if ($LASTEXITCODE -ne 0) {throw 'Fallo la instalacion Python'}
    } else {Write-Host 'Dependencias Python coinciden con el lock; no se reinstalan.'}
    if (-not $nodeReady -or ($installedHash -and $installedHash -ne $lockHash)) {
        Push-Location frontend
        try {& npm.cmd ci; if($LASTEXITCODE -ne 0){throw 'Fallo npm ci'}} finally {Pop-Location}
        Set-Content -LiteralPath $nodeStamp -Value $lockHash -Encoding ASCII
    } else {Write-Host 'Dependencias React coinciden con package-lock.json.'; Set-Content -LiteralPath $nodeStamp -Value $lockHash -Encoding ASCII}
    foreach ($pair in @(@('.env.example','.env'),@('frontend/.env.example','frontend/.env'))) {
        if (-not (Test-Path -LiteralPath $pair[1])) {Copy-Item -LiteralPath $pair[0] -Destination $pair[1]; Write-Host "Creado $($pair[1]) desde ejemplo, sin secretos."}
        else {Write-Host "Conservado $($pair[1]); no se sobrescribe."}
    }
}
& $python -m pip check
if ($LASTEXITCODE -ne 0) {throw 'Dependencias Python incompatibles'}
if (-not $SoloComprobar) {
    & $python -m scripts.private_paths
    if ($LASTEXITCODE -ne 0) {throw 'No se pudieron proteger archivos privados'}
}
& $python -c "import fastapi,sqlalchemy,psycopg,pgvector,onnxruntime,tokenizers,numpy,cryptography; print('Backend y RAG importables')"
if ($LASTEXITCODE -ne 0) {throw 'Faltan paquetes; ejecute la preparacion sin -SoloComprobar'}
foreach ($port in @(8000,5173)) {
    $listeners=@(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
    if ($listeners.Count) {Write-Warning "Puerto $port ocupado; el arranque verificara si pertenece a esta aplicacion."}
}
if ($PrepararModelo) {
    & $python -c "from dotenv import load_dotenv; load_dotenv('.env'); from backend.rag.embeddings import prepare_model; print(prepare_model()['revision'])"
    if ($LASTEXITCODE -ne 0) {throw 'No se pudo preparar/verificar el modelo oficial'}
}
& $python -c "from dotenv import dotenv_values; from pathlib import Path; v=dotenv_values('.env'); print('Configuracion privada pendiente' if not all(v.get(k) for k in ('DATABASE_USER','DATABASE_PASSWORD','AUTH_SECRET_KEY','AUTH_TOTP_KEYS')) else 'Variables privadas presentes'); p=v.get('RAG_MODEL_DIRECTORY'); print('Revise RAG_MODEL_DIRECTORY: ruta inexistente' if p and not Path(p).exists() else 'Ruta de modelo predeterminada o existente')"
& $python -m scripts.portability prerequisites
if ($LASTEXITCODE -ne 0) {
    if ($SoloComprobar) {throw 'PostgreSQL/pgvector/credenciales pendientes; consulte la guia'}
    Write-Warning 'PostgreSQL/pgvector o credenciales pendientes. Configure .env privado y repita -SoloComprobar.'
}
Write-Host 'Preparacion local completada. No se ejecuto ninguna migracion, restauracion, correo, LLM ni conexion Ubuntu.'
Write-Host 'Siguiente: recuperar .env y claves privadas, restaurar en base vacia y ejecutar python -m scripts.portability check --model.'
