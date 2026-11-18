$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$source = Join-Path $root '.local/install/pgvector-0.8.7'
$pg = 'C:/Program Files/PostgreSQL/18'
Copy-Item -LiteralPath "$source/vector.dll" -Destination "$pg/lib/vector.dll"
Copy-Item -LiteralPath "$source/vector.control" -Destination "$pg/share/extension/vector.control"
Get-ChildItem -LiteralPath "$source/sql" -Filter 'vector--*.sql' | Copy-Item -Destination "$pg/share/extension"
'pgvector instalado' | Set-Content "$root/.local/install/pgvector-ok.txt"
