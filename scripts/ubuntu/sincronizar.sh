#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
bash ./verificar.sh
if [[ $(systemctl show tacticlens-exportador.service -p Type --value) == simple ]]; then
    echo 'El emisor permanente ya sincroniza los cambios y reintenta pendientes; no se inicia otro ni se reactiva el timer.'
    exec sudo bash ./estado.sh
fi
# Pause scheduling and let any running oneshot finish before the same exporter
# performs a supervised immediate retry. Cowrie is never stopped.
sudo systemctl stop tacticlens-exportador.timer
trap 'sudo systemctl start tacticlens-exportador.timer' EXIT
for attempt in $(seq 1 60); do
    state=$(systemctl show tacticlens-exportador.service -p ActiveState --value)
    [[ $state != active && $state != activating && $state != deactivating ]] && break
    sleep 1
done
[[ $state != active && $state != activating && $state != deactivating ]] || { echo 'La exportacion sigue activa; espere su finalizacion'; exit 1; }
sudo python3 /opt/tacticlens-cowrie/exportar_eventos.py --retry-now
bash ./estado.sh
