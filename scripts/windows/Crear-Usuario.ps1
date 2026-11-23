[CmdletBinding()]
param(
    [switch]$BorrarCuentasAnteriores
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$pythonPath = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw 'Falta el entorno .venv del proyecto.'
}

Write-Host 'Registro de administrador de TacticLens'
Write-Host 'Ingrese los datos solicitados. La contraseña se introduce de forma oculta.'
if ($BorrarCuentasAnteriores) {
    Write-Host 'Se eliminarán cuentas, accesos, auditoría de autenticación y revisiones firmadas. Se conservarán las sesiones y eventos de Cowrie.'
}
Push-Location $projectRoot
try {
    $arguments = @('-m', 'scripts.create_admin')
    if ($BorrarCuentasAnteriores) {
        $arguments += '--reemplazar-cuentas'
    }
    & $pythonPath @arguments
    if ($LASTEXITCODE -ne 0) {
        throw 'No se pudo completar el registro.'
    }
}
finally {
    Pop-Location
}
