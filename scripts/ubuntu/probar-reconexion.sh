#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 1 && ($1 == antes || $1 == despues) ]] || { echo 'Uso: sudo bash probar-reconexion.sh antes|despues'; exit 1; }
umask 077
python3 - "$1" <<'PY'
import json,subprocess,sys
from pathlib import Path
snapshot=Path('/var/lib/tacticlens-cowrie/prueba-reconexion.json')
reader=Path('/opt/tacticlens-cowrie/event_status.py')
args=['python3',str(reader)] if reader.exists() else ['python3','/opt/tacticlens-cowrie/exportar_eventos.py','--status']
state=json.loads(subprocess.check_output(args,text=True))
if sys.argv[1]=='antes':
    if state.get('pendientes',0)<1:
        raise SystemExit('Genere eventos con el backend detenido y espere a su captura: debe haber pendientes antes de medir')
    snapshot.write_text(json.dumps(state));print('Muestra de pendientes guardada. Inicie de nuevo el backend y espere la sincronizacion HTTP.')
else:
    before=json.loads(snapshot.read_text())
    if state['total_cola']<before['total_cola'] or state['enviados']<before['enviados']+before['pendientes'] or state['pendientes'] or state['revision'] or state.get('revision_captura'):
        raise SystemExit('Recuperacion aun no demostrada: revise pendientes/revision, espere o ejecute sincronizar.sh')
    print('Los pendientes de la muestra fueron confirmados y permanecen conservados en SQLite. Contraste la sesion en la web.')
PY
