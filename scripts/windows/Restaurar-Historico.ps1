param([Parameter(Mandatory=$true)][string]$Respaldo, [string]$ClavesOriginales)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Set-Location $root
if (Test-Path .env) { throw 'Se conserva .env. No se ejecuta otra restauración automáticamente.' }
if (-not $ClavesOriginales) { $ClavesOriginales = "$Respaldo.auth.env" }
foreach ($file in @($Respaldo,"$Respaldo.json",$ClavesOriginales)) {
    if (-not (Test-Path -LiteralPath $file)) { throw "Falta archivo privado: $file" }
}
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
foreach ($file in @($Respaldo,"$Respaldo.json",$ClavesOriginales)) {
    & icacls.exe $file /inheritance:r /grant:r "*${sid}:F" '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo restringir el archivo privado.' }
}
Add-Type -AssemblyName System.Windows.Forms
$form = New-Object Windows.Forms.Form
$form.Text = 'PostgreSQL local: contraseña de postgres'
$form.Width = 460; $form.Height = 160; $form.StartPosition = 'CenterScreen'
$field = New-Object Windows.Forms.TextBox
$field.UseSystemPasswordChar = $true; $field.Left = 20; $field.Top = 20; $field.Width = 400
$button = New-Object Windows.Forms.Button
$button.Text = 'Restaurar en base NUEVA'; $button.Left = 20; $button.Top = 60; $button.Width = 220
$button.DialogResult = [Windows.Forms.DialogResult]::OK
$form.Controls.Add($field); $form.Controls.Add($button); $form.AcceptButton = $button
if ($form.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { $form.Dispose(); throw 'Cancelado' }
try {
    $env:TACTICLENS_PG_ADMIN_PASSWORD = $field.Text
    & ./.venv/Scripts/python.exe -m scripts.historical_database restore --config $ClavesOriginales --dump $Respaldo
    if ($LASTEXITCODE -ne 0) { throw 'Restauración pendiente: revise los registros privados.' }
} finally {
    Remove-Item Env:TACTICLENS_PG_ADMIN_PASSWORD -ErrorAction SilentlyContinue
    $field.Clear(); $form.Dispose()
}
& icacls.exe "$root/.env" /inheritance:r /grant:r "*${sid}:F" '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Revise permisos de .env' }
& ./.venv/Scripts/python.exe -m scripts.migrate
if ($LASTEXITCODE -ne 0) { throw 'Migraciones pendientes: no se inicia la aplicación.' }
& ./.venv/Scripts/python.exe -m scripts.demo_status --database
if ($LASTEXITCODE -ne 0) { throw 'Verificación pendiente' }
Write-Host 'Restauración y migraciones verificadas. 008 no se ejecutó. Ya puede iniciar TacticLens.'
