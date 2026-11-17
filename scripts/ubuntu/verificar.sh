#!/usr/bin/env bash
set -euo pipefail
systemctl is-active cowrie-tacticlens.service
if [[ $(systemctl show tacticlens-exportador.service -p Type --value) == simple ]]; then
    systemctl is-active tacticlens-exportador.service
    if systemctl is-active --quiet tacticlens-exportador.timer; then
        echo 'El modo inotify requiere el timer desactivado; revise antes de continuar'; exit 1
    fi
else
    systemctl is-active tacticlens-exportador.timer
fi
ss -lnt | grep -E ':2222[[:space:]]' >/dev/null || { echo 'Cowrie no escucha en 2222'; exit 1; }
sudo python3 - <<'PY'
import json,sys,urllib.request
sys.path.insert(0,'/opt/tacticlens-cowrie')
import sqlite_sender as sender
config=sender.read_env('/etc/tacticlens-cowrie/exportador.env')
url=config.get('TACTICLENS_URL','')
if config.get('TACTICLENS_TRANSPORT')!='demo-http':
    raise SystemExit('Falta configurar la modalidad demo-http')
sender.validate_endpoint(url,config.get('TACTICLENS_TOKEN',''),'demo-http')
try:
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),sender.NoRedirect())
    with opener.open(url.rsplit('/api/',1)[0]+'/api/health',timeout=5) as response:
        result=json.load(response)
    if result.get('contrato_ingesta')!='tacticlens.ingesta.v2' or result.get('database')!='connected':
        raise ValueError()
    print('HTTP local directo y PostgreSQL disponibles. Eventos persistidos:',result['ingestion']['eventos'])
except Exception:
    raise SystemExit('No se pudo confirmar la API por HTTP local: revise IP, firewall y aislamiento del hotspot') from None
PY
if systemctl is-active --quiet cowrie-ingest.service; then
    echo 'ERROR: el recolector directo anterior sigue activo; no habilitar otro emisor.' >&2
    exit 1
fi
echo 'Los servicios y el puerto son correctos. Verifique tambien pendientes con estado.sh.'
