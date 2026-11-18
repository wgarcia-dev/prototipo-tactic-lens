#!/usr/bin/env bash
set -euo pipefail
[[ $# -ge 2 && $# -le 3 ]] || { echo 'Uso: sudo bash configurar-http.sh RUTA_KIT IP_WINDOWS [ARCHIVO_CLAVE_PRIVADO]'; exit 1; }
bash "$(dirname -- "$0")/configurar.sh" "$@"
bash "$(dirname -- "$0")/verificar.sh"
bash "$(dirname -- "$0")/sincronizar.sh"
