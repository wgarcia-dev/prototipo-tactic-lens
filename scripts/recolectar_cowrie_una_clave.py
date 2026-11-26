"""Run the existing Cowrie catalog with one in-memory password per execution."""
import argparse
import getpass
import ipaddress
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
PORTS = {'cowrie_shell': 2222, 'cowrie_proxy': 2223, 'cowrie_llm': 2224}


def catalog(mode, selected):
    command = ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
               str(ROOT / 'scripts/windows/Probar-Cowrie.ps1'), '-Modalidad', mode,
               '-Port', str(PORTS[mode]), '-ExportarCatalogo']
    if selected:
        command += ['-Escenarios', ','.join(selected)]
    result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8-sig', check=True)
    items = json.loads(result.stdout)
    return items if isinstance(items, list) else [items]


def read_until_quiet(channel, max_seconds, quiet_seconds=0.7):
    pieces = []
    deadline = time.monotonic() + max_seconds
    last_data = time.monotonic()
    while time.monotonic() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(32768)
            if not chunk:
                break
            pieces.append(chunk.decode('utf-8', errors='replace'))
            last_data = time.monotonic()
        elif pieces and time.monotonic() - last_data >= quiet_seconds:
            break
        elif channel.closed:
            break
        time.sleep(0.1)
    return ''.join(pieces)


def run_case(paramiko, host, mode, user, password, case, marker, output):
    commands = ['echo "INICIO ' + marker + '"']
    commands += [line.replace('TL_WORK', marker).replace('TL_MARKER', marker)
                 for line in case['Commands']]
    commands += ['echo "FIN ' + marker + '"', 'exit']
    command_path = output / (marker + '.commands.txt')
    log_path = output / (marker + '.ssh.log')
    command_path.write_text('\n'.join(commands) + '\n', encoding='utf-8')
    started = datetime.now(timezone.utc)
    error = None
    code = 255
    chunks = []
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    known_hosts = Path.home() / '.ssh' / 'known_hosts'
    if known_hosts.exists():
        client.load_host_keys(str(known_hosts))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(host, port=PORTS[mode], username=user, password=password,
                       look_for_keys=False, allow_agent=False, timeout=10,
                       auth_timeout=12, banner_timeout=12)
        channel = client.invoke_shell(width=120, height=40)
        chunks.append(read_until_quiet(channel, 12))
        for line in commands:
            if channel.closed:
                raise RuntimeError('La sesión se cerró antes de completar el escenario')
            channel.send(line + '\n')
            chunks.append(read_until_quiet(channel, 25 if mode == 'cowrie_llm' else 8))
        chunks.append(read_until_quiet(channel, 3))
        code = 0 if 'FIN ' + marker in ''.join(chunks) else 1
    except Exception as exc:
        error = str(exc)
    finally:
        client.close()
    log_path.write_text(''.join(chunks), encoding='utf-8')
    return {'marcador': marker, 'modalidad': mode, 'escenario': case['Id'],
            'objetivo': case['Objetivo'], 'inicio_utc': started.isoformat(),
            'fin_utc': datetime.now(timezone.utc).isoformat(), 'destino': host,
            'puerto': PORTS[mode], 'codigo_ssh': code, 'error': error,
            'comandos': commands, 'log': str(log_path),
            'verificacion': 'Pendiente de contrastar con eventos Cowrie y TacticLens'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='192.168.56.101')
    parser.add_argument('--modalidades', nargs='+', choices=PORTS, default=list(PORTS))
    parser.add_argument('--escenarios', help='IDs separados por coma; use uno por modalidad')
    parser.add_argument('--usuario', default='root')
    parser.add_argument('--repeticiones', type=int, default=1)
    parser.add_argument('--solo-mostrar', action='store_true')
    args = parser.parse_args()
    address = ipaddress.ip_address(args.host)
    if address.version != 4 or not address.is_private or address.is_loopback:
        parser.error('Use la IPv4 privada del Cowrie del laboratorio')
    if not re.fullmatch(r'[A-Za-z0-9_-]+', args.usuario):
        parser.error('Usuario SSH inválido')
    if not 1 <= args.repeticiones <= 10:
        parser.error('Repeticiones debe estar entre 1 y 10')
    if 'cowrie_llm' in args.modalidades and args.repeticiones > 2:
        parser.error('LLM admite máximo dos repeticiones por ejecución')
    selected = args.escenarios.split(',') if args.escenarios else []
    cases = {mode: catalog(mode, selected) for mode in args.modalidades}
    if args.solo_mostrar:
        for mode, items in cases.items():
            print(mode, PORTS[mode])
            for item in items:
                print(' ', item['Id'], '-', item['Objetivo'], '(', len(item['Commands']), 'comandos)')
        return
    if 'cowrie_llm' in cases and sum(len(c['Commands']) for c in cases['cowrie_llm']) * args.repeticiones > 50:
        parser.error('Seleccione menos escenarios LLM: límite de 50 comandos por ejecución')
    try:
        import paramiko
    except ImportError:
        parser.error('Falta Paramiko. Instale con .\\.venv\\Scripts\\python.exe -m pip install "paramiko>=3.4,<5"')
    run_id = datetime.now(timezone.utc).strftime('TL-%Y%m%dT%H%M%SZ-') + uuid4().hex[:8]
    output = ROOT / '.local/pruebas-cowrie' / run_id
    output.mkdir(parents=True, exist_ok=False)
    password = getpass.getpass('Contraseña del señuelo Cowrie (solo una vez, no se guarda): ')
    results = []
    for mode, items in cases.items():
        for round_number in range(1, args.repeticiones + 1):
            for case in items:
                marker = f'{run_id}-{case["Id"]}-{round_number}'
                print(f'[{mode}] {marker}: {case["Objetivo"]}', flush=True)
                result = run_case(paramiko, args.host, mode, args.usuario, password, case, marker, output)
                results.append(result)
                (output / 'resultados.json').write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
                print('  cierre:', result['codigo_ssh'], result['error'] or '', flush=True)
    print('Manifiesto:', output / 'resultados.json')
    print('Verifique marcadores, eventos y análisis antes de exportar el CSV.')


if __name__ == '__main__':
    main()
