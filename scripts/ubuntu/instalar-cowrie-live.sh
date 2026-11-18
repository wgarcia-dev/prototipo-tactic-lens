#!/usr/bin/env bash
# Install on the Ubuntu VM that already uses my-honeypot and cowrie-ingest.env.
set -euo pipefail
umask 077
cd "$(dirname "$0")"
base=/opt/tacticlens-cowrie
state=/var/lib/tacticlens-cowrie
config=/etc/tacticlens-cowrie
log=/home/cowrie/my-honeypot/var/log/cowrie/cowrie.json
service=tacticlens-cowrie-live.service
for file in exportar_eventos.py sqlite_sender.py event_watch.py; do test -s "$file"; done
sudo -u cowrie test -r "$log"
for unit in tacticlens-exportador.timer tacticlens-exportador.service tacticlens-eventos.service; do
  if systemctl is-active --quiet "$unit"; then echo "Ya está activo $unit"; exit 1; fi
done
if [[ -e "$state/cola.sqlite3" && ! -f "/etc/systemd/system/$service" ]]; then
  echo "Existe una cola previa. Revise su servicio antes de instalar."; exit 1
fi
install -d -m 0755 "$base"
install -d -m 0750 -o root -g cowrie "$config"
install -d -m 0700 -o cowrie -g cowrie "$state"
install -m 0644 exportar_eventos.py sqlite_sender.py event_watch.py "$base/"
cd "$base"
python3 - <<'PY'
import os
from pathlib import Path
from sqlite_sender import read_env, validate_endpoint
cfg = read_env('/home/cowrie/.config/cowrie-ingest.env')
url, key = cfg['INGEST_URL'], cfg['INGEST_API_KEY']
validate_endpoint(url, key, 'demo-http')
dest = Path('/etc/tacticlens-cowrie/exportador.env')
tmp = dest.with_suffix('.installing')
tmp.write_text(f'TACTICLENS_URL={url}\nTACTICLENS_TOKEN={key}\nTACTICLENS_TRANSPORT=demo-http\n')
import grp
os.chown(tmp, 0, grp.getgrnam('cowrie').gr_gid)
tmp.chmod(0o640)
tmp.replace(dest)
PY
systemctl stop "$service" 2>/dev/null || true
sudo -u cowrie python3 - <<'PY'
import sqlite3
import exportar_eventos as e
with sqlite3.connect(e.DB) as conn:
    conn.execute('CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,payload TEXT NOT NULL,created_at TEXT NOT NULL)')
    conn.execute('CREATE TABLE IF NOT EXISTS cursor(name TEXT PRIMARY KEY,inode TEXT,offset INTEGER)')
    prepared = conn.execute("SELECT 1 FROM sqlite_master WHERE name='tacticlens_captura_origen'").fetchone()
if not prepared:
    e.prepare(e.DB, e.DB.parent/'backups')
PY
cat > "/etc/systemd/system/$service" <<'UNIT'
[Unit]
Description=TacticLens - envio automatico de Cowrie
After=network-online.target
Wants=network-online.target
[Service]
User=cowrie
Group=cowrie
WorkingDirectory=/opt/tacticlens-cowrie
ExecStart=/usr/bin/python3 -c "from pathlib import Path; import event_watch as w; w.exporter.LOG=Path('/home/cowrie/my-honeypot/var/log/cowrie/cowrie.json'); w.run()"
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
systemctl disable --now cowrie-ingest.service
systemctl daemon-reload
systemctl enable --now "$service"
systemctl --no-pager status "$service"
