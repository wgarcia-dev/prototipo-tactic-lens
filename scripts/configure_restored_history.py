"""Connect the restored history to FastAPI while verifying original MFA keys."""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess

from cryptography.fernet import Fernet, MultiFernet
from dotenv import dotenv_values, set_key
from scripts.historical_database import ROOT, connect


def configure(source_path):
    local = dotenv_values(ROOT/'.local/restauracion/restored-db.env')
    source = dotenv_values(source_path)
    for key in ('AUTH_SECRET_KEY', 'AUTH_TOTP_KEYS'):
        if not source.get(key):
            raise RuntimeError('Falta clave privada original: '+key)
    if len(source['AUTH_SECRET_KEY']) < 64:
        raise RuntimeError('AUTH_SECRET_KEY no cumple la configuración del backend integrado')
    cipher = MultiFernet([Fernet(key.strip().encode()) for key in source['AUTH_TOTP_KEYS'].split(',')])
    with connect(local) as conn:
        conn.execute('SET TRANSACTION READ ONLY')
        rows = conn.execute('SELECT secreto_cifrado FROM honeypot.auth_factor').fetchall()
        for (encrypted,) in rows:
            # Verify all restored factors can be decrypted; never reveal TOTP secrets.
            cipher.decrypt(encrypted.encode())
        if source.get('HONEYPOT_ID'):
            if not conn.execute('SELECT 1 FROM honeypot.honeypot WHERE id_honeypot=%s', (source['HONEYPOT_ID'],)).fetchone():
                raise RuntimeError('El sensor del archivo privado no pertenece a la copia restaurada')
            local['HONEYPOT_ID'] = source['HONEYPOT_ID']
    if not local.get('HONEYPOT_ID'):
        raise RuntimeError('Hay varios sensores; seleccione el HONEYPOT_ID original')
    target = ROOT/'.env'
    if target.exists():
        raise RuntimeError('Existe .env; se conserva sin sobrescribir')
    values = dict(local)
    values.update(AUTH_SECRET_KEY=source['AUTH_SECRET_KEY'], AUTH_TOTP_KEYS=source['AUTH_TOTP_KEYS'],
                  AUTH_ENV='development', AUTH_COOKIE_SECURE='false', AUTH_PUBLIC_URL='http://127.0.0.1:5173',
                  AUTH_ALLOWED_ORIGINS='http://127.0.0.1:5173,http://localhost:5173', MAIL_TRANSPORT='file',
                  MAIL_DEV_DIRECTORY='.local/mail', INGEST_API_KEY=secrets.token_urlsafe(32),
                  LLM_MODE='real', LLM_PROVIDER='deepseek', LLM_BASE_URL='https://api.deepseek.com',
                  LLM_API_KEY=source.get('LLM_API_KEY') or '', LLM_MODEL=source.get('LLM_MODEL') or '',
                  MAIL_TIMEZONE='America/Guayaquil')
    target.touch(exist_ok=False)
    identity = subprocess.run(['whoami', '/user', '/fo', 'csv', '/nh'], check=True, capture_output=True, text=True).stdout
    import csv
    sid = next(csv.reader([identity.strip()]))[1]
    subprocess.run(['icacls.exe', str(target), '/inheritance:r', '/grant:r', '*'+sid+':F',
                    '*S-1-5-18:F', '*S-1-5-32-544:F'], check=True, stdout=subprocess.DEVNULL)
    for key, value in values.items():
        if value is not None:
            set_key(target, key, value)
    print(f'FastAPI configurado. {len(rows)} factores MFA restaurados descifran correctamente; no se imprimió ningún secreto.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--auth-file', required=True, type=Path)
    args = parser.parse_args()
    try:
        configure(args.auth_file)
    except Exception as exc:
        detail = str(exc) if isinstance(exc, RuntimeError) else 'No se configuró acceso: revise archivo original y claves MFA.'
        raise SystemExit(type(exc).__name__+': '+detail) from None
