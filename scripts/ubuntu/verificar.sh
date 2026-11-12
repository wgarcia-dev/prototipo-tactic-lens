#!/usr/bin/env bash
set -euo pipefail
systemctl is-active cowrie-tacticlens.service
systemctl is-active tacticlens-exportador.timer
ss -lnt | grep -E ':2222[[:space:]]' >/dev/null || { echo 'Cowrie no escucha en 2222'; exit 1; }
# A remote sshd with GatewayPorts=yes may override a requested loopback bind.
python3 - <<'PY'
import json,subprocess,urllib.request
lines=[line for line in subprocess.check_output(['ss','-H','-lnt'],text=True).splitlines() if line.split()[3].rsplit(':',1)[-1]=='18765']
if not lines or any(line.split()[3]!='127.0.0.1:18765' for line in lines):
    raise SystemExit('Tunel ausente o publicado fuera de loopback. Revise GatewayPorts=no/clientspecified; no continuar.')
try:
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://127.0.0.1:18765/api/health',timeout=5) as response:
        result=json.load(response)
    if result.get('contrato_ingesta')!='tacticlens.ingesta.v2' or result.get('database')!='connected':
        raise ValueError()
    print('Tunel cifrado en loopback y backend real compatibles. Eventos persistidos:',result['ingestion']['eventos'])
except Exception:
    raise SystemExit('No se pudo confirmar la API real de TacticLens a traves del tunel') from None
PY
if systemctl is-active --quiet cowrie-ingest.service; then
    echo 'ERROR: el recolector directo anterior sigue activo; no habilitar otro emisor.' >&2
    exit 1
fi
echo 'Los servicios y el puerto son correctos. Verifique tambien pendientes con estado.sh.'
