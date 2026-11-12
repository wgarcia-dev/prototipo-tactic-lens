#!/usr/bin/env bash
# Upgrade the exporter actually inspected in diagnostico_tacticlens.json.
set -euo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Ejecute con sudo desde Ubuntu'; exit 1; }
[[ $# -eq 1 ]] || { echo 'Uso: configurar.sh RUTA_KIT'; exit 1; }
kit=$(realpath -- "$1")
exporter=/opt/tacticlens-cowrie/exportar_eventos.py
queue=/var/lib/tacticlens-cowrie/cola.sqlite3
config=/etc/tacticlens-cowrie/exportador.env
[[ -f $exporter && -f $queue && -f $config ]] || { echo 'Falta un archivo real de la instalacion; no se modifica nada'; exit 1; }
[[ $(systemctl show tacticlens-exportador.service -p Type --value) == oneshot ]] || { echo 'Revise la unidad: se requiere Type=oneshot'; exit 1; }
[[ $(systemctl show tacticlens-exportador.service -p RemainAfterExit --value) == no ]] || { echo 'Revise RemainAfterExit'; exit 1; }
[[ -z $(systemctl show tacticlens-exportador.service -p ExecStartPost --value) ]] || { echo 'Existe otro ExecStartPost; reviselo antes de instalar otro emisor'; exit 1; }
python3 - "$kit" "$exporter" "$queue" <<'PY'
import hashlib,importlib.util,sqlite3,sys
from pathlib import Path
from urllib.parse import quote
kit,exporter,queue=sys.argv[1:]
known='36f42dc347ef33d4899536ce2bba7a17bd8f0268fc023b8fe0142d9ea7c17003'
actual=hashlib.sha256(Path(exporter).read_bytes()).hexdigest()
new=hashlib.sha256((Path(kit)/'collector/exportar_eventos.py').read_bytes()).hexdigest()
if actual not in {known,new}:
    raise SystemExit('El exportador cambio respecto al diagnostico. Revise el nuevo codigo antes de instalar.')
sys.path.insert(0,str(Path(kit)/'collector'))
import exportar_eventos
with sqlite3.connect('file:'+quote(queue,safe='/')+'?mode=ro',uri=True) as conn:
    exportar_eventos.mapping(conn)
PY
read -rsp 'Clave INGEST_API_KEY del .env de Windows (se guardara como TACTICLENS_TOKEN): ' ingest_key
printf '
'
[[ $ingest_key =~ ^[A-Za-z0-9_-]{32,}$ ]] || { echo 'Clave no valida'; exit 1; }
stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup=/var/lib/tacticlens-cowrie/backups/instalacion-$stamp
install -d -m 0700 "$backup"
cp -p -- "$exporter" "$backup/"
cp -p -- "$config" "$backup/"
systemctl cat tacticlens-exportador.service > "$backup/servicio-anterior.txt"
systemctl cat tacticlens-exportador.timer > "$backup/timer-anterior.txt"
systemctl stop tacticlens-exportador.timer
completed=0
restore_timer() {
    if [[ $completed -eq 0 ]]; then
        cp -p -- "$backup/exportar_eventos.py" "$exporter"
        cp -p -- "$backup/exportador.env" "$config"
        echo 'Instalacion incompleta: script/configuracion restaurados y timer pausado para no reenviar al receptor anterior. Cowrie sigue capturando. Revise antes de reactivar.' >&2
    else
        systemctl start tacticlens-exportador.timer
    fi
}
trap restore_timer EXIT
for attempt in $(seq 1 60); do
    state=$(systemctl show tacticlens-exportador.service -p ActiveState --value)
    [[ $state != active && $state != activating && $state != deactivating ]] && break
    sleep 1
done
[[ $state != active && $state != activating && $state != deactivating ]] || { echo 'La captura sigue activa; no continuar'; exit 1; }
install -m 0644 "$kit/collector/sqlite_sender.py" /opt/tacticlens-cowrie/sqlite_sender.py
install -m 0755 "$kit/collector/exportar_eventos.py" "$exporter"
python3 "$exporter" --prepare
# Edit only the existing configuration keys; no extra SMTP/backend/queue.
TACTICLENS_KEY_INPUT=$ingest_key python3 - "$config" <<'PY'
import os,re,sys
from pathlib import Path
p=Path(sys.argv[1]);s=p.read_text()
for key,value in {'TACTICLENS_URL':'http://127.0.0.1:18765/api/ingesta/eventos','TACTICLENS_TOKEN':os.environ['TACTICLENS_KEY_INPUT']}.items():
    line=key+'='+value
    pattern=r'(?m)^(?:export\s+)?'+key+r'\s*=.*$'
    s=re.sub(pattern,lambda _:line,s) if re.search(pattern,s) else s.rstrip()+'\n'+line+'\n'
tmp=p.with_suffix('.env.tmp');tmp.write_text(s)
os.chmod(tmp,0o600);os.chown(tmp,p.stat().st_uid,p.stat().st_gid);os.replace(tmp,p)
PY
unset ingest_key
if systemctl cat cowrie-ingest.service >/dev/null 2>&1; then systemctl disable --now cowrie-ingest.service; fi
completed=1
systemctl enable tacticlens-exportador.timer
python3 "$exporter" --status
echo "Actualizacion preparada. Respaldo privado: $backup"
echo 'Se conserva el timer y su servicio. Ejecute verificar.sh y sincronizar.sh para comprobar el tunel y los envios.'
