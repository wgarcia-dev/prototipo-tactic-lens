$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot 'Iniciar-TacticLens.ps1') -Detener
if ($LASTEXITCODE -ne 0) {throw 'Revise el apagado de los procesos propios de TacticLens.'}
