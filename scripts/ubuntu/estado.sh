#!/usr/bin/env bash
set -euo pipefail
if [[ -f /opt/tacticlens-cowrie/event_status.py ]]; then
    exec python3 /opt/tacticlens-cowrie/event_status.py
fi
exec python3 /opt/tacticlens-cowrie/exportar_eventos.py --status
