"""Export controlled Cowrie scenarios joined to persisted evidence and analyses."""
import argparse
import csv
import json
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import text

from backend.db import database_engine


FIELDS = ('ejecucion', 'escenario', 'objetivo', 'marcador', 'modalidad_planificada',
          'puerto_planificado', 'codigo_ssh', 'id_sesion', 'cowrie_session_id',
          'modalidad_registrada', 'puerto_registrado', 'inicio_sesion', 'eventos_sesion',
          'eventos_con_marcador', 'comandos_observados_json', 'id_analisis',
          'estado_analisis', 'fecha_analisis', 'resumen_analisis',
          'resultado_estructurado_json', 'estado_vinculacion')


def export(source, destination, only_completed=False):
    load_dotenv()
    destination.parent.mkdir(parents=True, exist_ok=True)
    manifests = sorted(source.glob('TL-*/resultados.json'))
    if not manifests:
        raise SystemExit('No se encontraron manifiestos')
    matched = text('''SELECT s.id_sesion, s.cowrie_session_id, s.puerto_destino,
        s.fecha_inicio, count(*) AS marcadores
        FROM honeypot.sesion s JOIN honeypot.evento e ON e.id_sesion=s.id_sesion
        WHERE e.datos_originales::text LIKE :marker
        GROUP BY s.id_sesion ORDER BY marcadores DESC, s.fecha_inicio DESC''')
    details = text('''SELECT s.id_honeypot, count(e.id_evento) AS eventos,
        coalesce(jsonb_agg(e.datos_originales->>'input' ORDER BY e.numero_secuencia)
            FILTER (WHERE e.tipo_evento='cowrie.command.input'), '[]'::jsonb) AS comandos
        FROM honeypot.sesion s LEFT JOIN honeypot.evento e ON e.id_sesion=s.id_sesion
        WHERE s.id_sesion=:session GROUP BY s.id_sesion''')
    analysis = text('''SELECT id_analisis, estado, fecha_fin, resumen, resultado_estructurado
        FROM honeypot.analisis_llm WHERE id_sesion=:session
        ORDER BY CASE WHEN estado='completado' THEN 0 ELSE 1 END,
                 fecha_fin DESC NULLS LAST, creado_en DESC LIMIT 1''')
    modes = text('''SELECT id_honeypot, nombre FROM honeypot.honeypot
        WHERE id_honeypot IN (:shell,:proxy,:llm)''')
    import os
    identifiers = {mode: os.getenv('HONEYPOT_ID_COWRIE_' + mode.upper()) for mode in ('shell','proxy','llm')}
    labels = {value: mode for mode, value in identifiers.items() if value}
    counts = {'filas': 0, 'vinculadas': 0, 'analizadas': 0, 'ambiguas': 0}
    with database_engine().connect() as conn, destination.open('w', newline='', encoding='utf-8-sig') as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        for manifest in manifests:
            for case in json.loads(manifest.read_text(encoding='utf-8-sig')):
                marker = case['marcador']
                sessions = conn.execute(matched, {'marker': '%' + marker + '%'}).mappings().all()
                row = dict.fromkeys(FIELDS, '')
                row.update(ejecucion=manifest.parent.name, escenario=case['escenario'],
                    objetivo=case.get('objetivo', ''), marcador=marker,
                    modalidad_planificada=case.get('modalidad') or {2222:'shell',2223:'proxy',2224:'llm'}.get(case.get('puerto'),''),
                    puerto_planificado=case.get('puerto'), codigo_ssh=case.get('codigo_ssh'))
                if len(sessions) == 1:
                    session = sessions[0]
                    evidence = conn.execute(details, {'session': session['id_sesion']}).mappings().one()
                    result = conn.execute(analysis, {'session': session['id_sesion']}).mappings().first()
                    row.update(id_sesion=str(session['id_sesion']), cowrie_session_id=session['cowrie_session_id'],
                        modalidad_registrada=labels.get(str(evidence['id_honeypot']), 'desconocido'),
                        puerto_registrado=session['puerto_destino'], inicio_sesion=session['fecha_inicio'].isoformat(),
                        eventos_sesion=evidence['eventos'], eventos_con_marcador=session['marcadores'],
                        comandos_observados_json=json.dumps(evidence['comandos'], ensure_ascii=False),
                        estado_vinculacion='unica')
                    counts['vinculadas'] += 1
                    if result:
                        row.update(id_analisis=str(result['id_analisis']), estado_analisis=result['estado'],
                            fecha_analisis=result['fecha_fin'].isoformat() if result['fecha_fin'] else '',
                            resumen_analisis=result['resumen'] or '',
                            resultado_estructurado_json=json.dumps(result['resultado_estructurado'], ensure_ascii=False)
                                if result['resultado_estructurado'] else '')
                        counts['analizadas'] += result['estado'] == 'completado'
                else:
                    row['estado_vinculacion'] = 'sin_sesion' if not sessions else 'ambigua'
                    counts['ambiguas'] += len(sessions) > 1
                if not only_completed or (row['estado_vinculacion'] == 'unica'
                        and row['estado_analisis'] == 'completado'
                        and row['modalidad_registrada'] in ('shell', 'proxy', 'llm')):
                    writer.writerow(row)
                    counts['filas'] += 1
    return counts


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=Path('.local/pruebas-cowrie'))
    parser.add_argument('--output', type=Path, default=Path('datasets/cowrie_sesiones_2026-11-26.csv'))
    parser.add_argument('--solo-completados', action='store_true')
    args = parser.parse_args()
    print(json.dumps(export(args.source, args.output, args.solo_completados), ensure_ascii=False))
