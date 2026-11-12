#!/usr/bin/env bash
# Run from the Ubuntu console when moving to a hotspot with a different subnet.
set -euo pipefail
[[ $EUID -eq 0 && $# -eq 1 ]] || { echo 'Uso: sudo bash autorizar-windows.sh IP_PRIVADA_WINDOWS'; exit 1; }
python3 - "$1" <<'PY'
import ipaddress,sys
address=ipaddress.IPv4Address(sys.argv[1])
if not any(address in ipaddress.IPv4Network(net) for net in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
    raise SystemExit('Indique la direccion privada actual de Windows, no una red ni una IP publica')
PY
ufw status | grep -q '^Status: active' || { echo 'UFW no esta activo; revise su estado sin deshabilitarlo'; exit 1; }
ufw allow proto tcp from "$1" to any port 22 comment 'TacticLens SSH laptop Windows'
ufw allow proto tcp from "$1" to any port 2222 comment 'TacticLens prueba Cowrie Windows'
echo 'Solo se agregaron reglas para esa direccion. No se abrio 18765 ni se modificaron SSH o las reglas anteriores.'
