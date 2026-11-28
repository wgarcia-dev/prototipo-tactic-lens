param(
    [Parameter(Mandatory=$true)][string]$Respaldo,
    [string]$ClavesOriginales
)
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Set-Location $root
if(Test-Path .env) { throw 'Existe .env; se conserva sin reemplazar.' }
if(Test-Path .local/restauracion/restored-db.env) { throw 'Ya hay una base restaurada registrada. No se crea otra automáticamente.' }
if(-not(Test-Path -LiteralPath $Respaldo)) { throw 'No existe el respaldo indicado.' }
$private=Join-Path $root '.local/restauracion'
New-Item -ItemType Directory -Force $private | Out-Null
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $private /inheritance:r /grant:r "*${sid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if($LASTEXITCODE -ne 0) { throw 'No se pudieron restringir los archivos privados.' }
& ./.venv/Scripts/python.exe -m scripts.restore_existing_archive $Respaldo
if($LASTEXITCODE -ne 0) { throw 'El archivo no pasó la inspección completa; no se restaura.' }
Add-Type -AssemblyName System.Windows.Forms
$form=New-Object Windows.Forms.Form
$form.Text='TacticLens: contraseña de postgres local (solo memoria)'
$form.Width=510; $form.Height=165; $form.StartPosition='CenterScreen'; $form.TopMost=$true
$field=New-Object Windows.Forms.TextBox
$field.Left=15; $field.Top=20; $field.Width=465; $field.UseSystemPasswordChar=$true
$button=New-Object Windows.Forms.Button
$button.Text='Restaurar en base NUEVA'; $button.Left=15; $button.Top=65; $button.Width=230
$button.DialogResult=[Windows.Forms.DialogResult]::OK
$form.Controls.AddRange(@($field,$button)); $form.AcceptButton=$button
if($form.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { $form.Dispose(); throw 'Cancelado' }
try {
    $env:TACTICLENS_PG_ADMIN_PASSWORD=$field.Text
    $field.Clear(); $form.Dispose()
    & ./.venv/Scripts/python.exe -m scripts.restore_existing_archive $Respaldo --restore
    if($LASTEXITCODE -ne 0) { throw 'Restauración pendiente. Consulte los registros privados.' }
} finally {
    Remove-Item Env:TACTICLENS_PG_ADMIN_PASSWORD -ErrorAction SilentlyContinue
}
if($ClavesOriginales) {
    & ./.venv/Scripts/python.exe -m scripts.configure_restored_history --auth-file $ClavesOriginales
    if($LASTEXITCODE -ne 0) { throw 'Datos restaurados; configuración MFA original pendiente.' }
    & ./.venv/Scripts/python.exe -m scripts.db_roles
    if($LASTEXITCODE -ne 0) { throw 'Revise los permisos operativos de la base restaurada.' }
} else {
    Write-Host 'Datos restaurados. Falta el archivo privado AUTH_SECRET_KEY/AUTH_TOTP_KEYS para habilitar el acceso original.'
}
