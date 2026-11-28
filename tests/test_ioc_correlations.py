"""Expected evidence labels for Cowrie relationships and MITRE joins."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

import test_auth as fixtures
from backend.api import app
from backend.correlation import transfer_correlations, transfer_window
from backend.ioc_views import public_payload, technical_profile
from backend.rag.behavior import represent
from backend.routes import AnalysisResult, Finding, IocProposal, MitreProposal


class TemporalEvidenceTests(TestCase):
    def test_observable_profile_address_classes_and_safe_context(self):
        for address, version, scope in (
            ("192.168.1.120",4,"privada"), ("8.8.8.8",4,"global"),
            ("2001:4860:4860::8888",6,"global"), ("::1",6,"loopback"), ("fe80::1",6,"enlace_local"),
            ("::ffff:192.168.1.110",6,"privada"), ("240.0.0.1",4,"reservada"), ("ff02::1",6,"multicast"),
        ):
            self.assertEqual(technical_profile("IP",address),{"version_ip":version,"alcance":scope})
        actual = public_payload({"input":"wget https://user:fixture@public.test/download?opaque=fixture",
                                 "password":"fixture", "output":"fixture",
                                 "note":"-----BEGIN OPENSSH PRIVATE KEY-----\nfixture"})
        self.assertNotIn("fixture",str(actual))
        self.assertEqual(actual["input"],"wget https://public.test/download")
        self.assertNotIn("fixture",public_payload("curl -H 'Cookie: session=fixture' --data 'secret=fixture' https://public.test"))
        self.assertEqual(technical_profile("Hash","a"*64),{"algoritmo":"SHA-256"})

    def row(self, event_id, seconds, *, command=False, session="one"):
        return {
            "id_evento": event_id, "id_sesion": session, "numero_secuencia": event_id,
            "fecha_hora": datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds),
            "ingresado_en": datetime(2026, 3, 1, tzinfo=timezone.utc),
            "tipo_evento": "cowrie.command.input" if command else "cowrie.session.file_download",
            "detalles": [{"comportamiento": "intento_descarga" if command else "descarga_registrada"}],
        }

    def test_equal_timestamps_are_ambiguous_and_success_before_command_is_excluded(self):
        tied = transfer_correlations([self.row(1, 8), self.row(20, 8, command=True)], {1, 20})
        self.assertEqual({r["estado"] for r in tied.values()}, {"candidata"})
        earlier = transfer_correlations([self.row(1, 7), self.row(20, 8, command=True)], {1, 20})
        self.assertEqual({r["estado"] for r in earlier.values()}, {"insuficiente"})

    def test_one_command_with_two_outcomes_is_ambiguous_on_both_sides(self):
        items = [self.row(3, 5), self.row(2, 4), self.row(1, 1, command=True), self.row(10, 0, command=True, session="other")]
        got = transfer_correlations(items, {1, 2, 3, 10})
        self.assertEqual([got[i]["estado"] for i in (1, 2, 3, 10)], [
            "candidata", "candidata", "candidata", "insuficiente"])
        self.assertEqual(got[1]["total_candidatos"], 2)

    def test_window_is_optional_and_includes_its_boundary(self):
        items = [self.row(1, 0, command=True), self.row(2, 4)]
        self.assertEqual(transfer_correlations(items, {2}, transfer_window("4"))[2]["estado"], "contextual")
        self.assertEqual(transfer_correlations(items, {2}, transfer_window("3"))[2]["estado"], "insuficiente")
        self.assertIsNone(transfer_window("  "))
        for invalid in ("-4", "0", "one", "2.5"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                transfer_window(invalid)


class CorrelationApiTests(fixtures.AuthFixture):
    URL_A = "https://files.corp.local/tool?a=1&b=2"
    URL_B = "https://files.corp.local/tool?a=2&b=1"
    URL_C = "https://other.corp.local/tool"
    DIGEST = "Ab89" * 16
    IP = "10.110.15.28"

    def event(self, session, seconds, kind="cowrie.command.input", **fields):
        return {
            "session": session, "eventid": kind, "timestamp": (self.clock + timedelta(seconds=seconds)).isoformat(),
            "src_ip": self.IP, "_collector": {"source_id": "etapa2:" + uuid4().hex}, **fields,
        }

    def ingest(self, rows):
        response = self.client.post("/api/ingesta/eventos", json={"eventos": rows},
                                    headers={"X-API-Key": app.state.api_key})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def session_id(self, event_id):
        e = app.state.tables["evento"]
        return self.connection.scalar(select(e.c.id_sesion).where(e.c.id_evento == event_id))

    def ioc_id(self, value):
        ioc = app.state.tables["ioc"]
        return self.connection.scalar(select(ioc.c.id_ioc).where(ioc.c.valor == value))

    def observations(self, value):
        result = self.client.get(f"/api/iocs/{self.ioc_id(value)}/observaciones")
        self.assertEqual(result.status_code, 200, result.text)
        return {int(row["id_evento"]): row for row in result.json()}

    def validate_relation(self, observation, name, expected):
        correlation, = [item for item in observation["correlaciones"] if item["tipo"] == name]
        self.assertEqual(correlation["estado"], expected)
        return correlation

    def local_rag(self, events, modality, sample=None):
        tables = app.state.tables
        catalog, tech = tables["catalogo_mitre"], tables["tecnica_mitre"]
        current = self.connection.execute(select(catalog.c.id_catalogo, catalog.c.version,catalog.c.sha256).where(catalog.c.activo)).one()
        tactics = {"T1105": "TA0011", "T1082": "TA0007", "T1059.004": "TA0002"}
        candidates = [
            {"codigo_tecnica": row.codigo_tecnica, "nombre": row.nombre,
             "objeto_sha256": row.objeto_sha256, "observabilidad": "intento_evaluable",
             "stix_id": row.stix_id, "tacticas": [{"codigo_tactica": tactics[row.codigo_tecnica]}],"plataformas":["Linux"],
             "puntuacion_hibrida": 0.03, "similitud_vectorial": 0.8}
            for row in self.connection.execute(select(tech.c.codigo_tecnica, tech.c.nombre, tech.c.objeto_sha256,
                tech.c.stix_id).where(tech.c.codigo_tecnica.in_(tactics)))
        ]
        return {"catalogo": {"id_catalogo": str(current.id_catalogo), "version": current.version,"sha256":current.sha256},
                "metodo": "deepseek_rag_mitre_v1", "modelo_embeddings": {"nombre": "fixture local"},
                "candidatos": candidates, "representacion": represent(events)}

    @staticmethod
    def proposal(code, tactic, events):
        return MitreProposal(codigo=code, codigo_tactica=tactic, eventos=events,
            comportamiento_observado="Orden registrada por Cowrie",
            justificacion="El comportamiento registrado en Cowrie respalda la propuesta de técnica.",
            limitaciones=["El entorno emulado limita el alcance de la evidencia."])

    def analyze_fixture(self, session, result):
        with patch("backend.routes.real_result", return_value=result), patch("backend.routes.rag_context", side_effect=self.local_rag):
            response = self.client.post(f"/api/sesiones/{session}/analizar")
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["id_analisis"]

    def test_mitre_browser_groups_distinct_sessions_and_preserves_historical_details(self):
        self.enroll(826)
        sensor = uuid4()
        self.connection.execute(app.state.tables['honeypot'].insert().values(id_honeypot=sensor,nombre='Shell browser',host='loopback'))
        namespace = uuid4().hex
        created = []
        with patch.object(app.state,'instances',{'cowrie_shell':sensor}):
            for suffix,action_count in (('alpha',2),('beta',1)):
                raw = self.event(f'{namespace}-{suffix}',1,input=f"wget '{self.URL_A}'")
                raw['_collector']['instance_id']='cowrie_shell'
                eid = self.ingest([raw])['confirmaciones'][0]['id_evento']
                sid = self.session_id(eid)
                result = AnalysisResult(resumen='Intención de descarga registrada',acciones=[
                    Finding(tipo=f'Comando {index}',descripcion='Acción de Cowrie',confianza=0.8,eventos=[eid],
                            iocs=[IocProposal(tipo='URL',valor=self.URL_A,evento=eid)],
                            mitre=[self.proposal('T1105','TA0011',[eid])]) for index in range(action_count)
                ])
                aid = self.analyze_fixture(sid,result)
                created.append((sid,aid,eid))

            first_sid,first_aid,first_eid = created[0]
            stored = self.client.get(f'/api/analisis/{first_aid}').json()
            current,legacy = [row['mitre'][0] for row in stored['acciones']]
            mapping = app.state.tables['mapeo_mitre']
            provenance = {key:value for key,value in legacy['rag_procedencia'].items() if key!='clasificacion'}
            self.connection.execute(mapping.update().where(mapping.c.id_mapeo==UUID(legacy['id_mapeo'])).values(rag_procedencia=provenance))

            filters = {'sesion':namespace,'tactica':'TA0011','modalidad':'cowrie_shell','q':'Ingress Tool Transfer'}
            groups = self.client.get('/api/mitre/tecnicas',params=filters)
            self.assertEqual(groups.status_code,200,groups.text)
            technique, = groups.json()
            self.assertEqual((technique['codigo_tecnica'],technique['sesiones']),('T1105',2))
            self.assertEqual(set(technique['estados']),{'automatica','historica_pendiente'})
            summary = self.client.get('/api/mitre/resumen', params=filters)
            self.assertEqual(summary.status_code, 200, summary.text)
            body = summary.json()
            self.assertEqual(body['version_catalogo'], '20.1')
            self.assertEqual({key: body['totales'][key] for key in ('tecnicas','tacticas','sesiones','mapeos','eventos_citados','con_citas','pendientes')},
                             {'tecnicas':1,'tacticas':1,'sesiones':2,'mapeos':3,'eventos_citados':2,'con_citas':3,'pendientes':3})
            self.assertEqual({row['estado_identificacion']: row['pendientes'] for row in body['estados']},
                             {'automatica': 2, 'historica_pendiente': 1})
            self.assertEqual([(row['codigo_tactica'],row['mapeos']) for row in body['tacticas']], [('TA0011',3)])
            self.assertEqual([(row['modalidad'],row['mapeos']) for row in body['modalidades']], [('cowrie_shell',3)])
            self.assertTrue(all(row['origen_fecha']=='evento_citado' for row in body['evolucion']))
            supported = self.client.get('/api/mitre/resumen',
                                        params={**filters,'plataforma':'Linux','ip':self.IP,'citas':'con','grado':'intento'})
            self.assertEqual(supported.json()['totales']['mapeos'],3)
            empty = self.client.get('/api/mitre/resumen', params={**filters,'hasta':'2000-01-01'})
            self.assertEqual(empty.json()['totales']['mapeos'],0)
            local_day = (self.clock + timedelta(seconds=1)).astimezone(ZoneInfo('America/Guayaquil')).date().isoformat()
            day = self.client.get('/api/mitre/resumen', params={**filters,'desde':local_day,'hasta':local_day})
            self.assertEqual(day.json()['totales']['mapeos'],3)
            self.assertEqual(self.client.get('/api/mitre/resumen', params={'desde':'2010-01-01','hasta':'2000-01-01'}).status_code,422)
            cell, = self.client.get('/api/mitre/matriz', params=filters).json()
            self.assertEqual((cell['codigo_tecnica'],cell['codigo_tactica'],cell['mapeos']),('T1105','TA0011',3))
            catalog = self.client.get('/api/mitre/matriz', params={**filters,'catalogo':True}).json()
            self.assertTrue(any(row['mapeos']==0 and row['relacion_vigente'] for row in catalog))
            detail = self.client.get('/api/mitre/tecnicas/T1105', params=filters)
            self.assertEqual(detail.status_code,200,detail.text)
            self.assertEqual(detail.json()['totales']['observables'],1)
            self.assertIn('Linux', detail.json()['catalogo']['plataformas'])
            official_child = self.client.get('/api/mitre/tecnicas/T1059.004').json()['catalogo']
            self.assertEqual((official_child['nombre'],official_child['tecnica_padre_id']),('Unix Shell','T1059'))
            group_path = '/api/mitre/tecnicas/T1105/sesiones'
            grouped = self.client.get(group_path,params=filters).json()
            self.assertEqual({row['id_sesion']:row['mapeos'] for row in grouped},
                             {str(first_sid):2,str(created[1][0]):1})
            self.assertTrue(all(row['modalidades']==['cowrie_shell'] for row in grouped))
            historical, = self.client.get(group_path,params={**filters,'estado':'historica_pendiente'}).json()
            self.assertEqual((historical['id_sesion'],historical['mapeos']),(str(first_sid),1))
            self.assertEqual(self.client.get(group_path,params={**filters,'modalidad':'cowrie_proxy'}).json(),[])
            self.assertEqual(self.client.get(group_path,params={**filters,'estado':'invalid'}).status_code,422)
            page_one, = self.client.get(group_path,params={**filters,'limit':1}).json()
            page_two, = self.client.get(group_path,params={**filters,'limit':1,'offset':1}).json()
            self.assertNotEqual(page_one['id_sesion'],page_two['id_sesion'])

            listed = self.client.get('/api/mitre/mapeos',params={**filters,'codigo':'T1105','id_sesion':str(first_sid)}).json()
            self.assertEqual({row['id_mapeo'] for row in listed},{current['id_mapeo'],legacy['id_mapeo']})
            self.assertEqual({row['estado_identificacion'] for row in listed},{'automatica','historica_pendiente'})
            reloaded = self.client.get(f'/api/mitre/mapeos/{current["id_mapeo"]}/observables').json()['mapeo']
            for field in ('codigo_tecnica','justificacion','grado_evidencia','estado_revision','eventos'):
                self.assertEqual(reloaded[field],current[field])
            self.assertEqual(reloaded['eventos'][0]['id_evento'],str(first_eid))
            self.assertEqual(reloaded['eventos'][0]['id_sesion'],str(first_sid))
            self.assertEqual(reloaded['estado_revision'],'pendiente')
            expanded = self.client.get(f'/api/mitre/mapeos/{current["id_mapeo"]}/observables',params={'detallar_citas':True}).json()
            self.assertIn('wget',expanded['mapeo']['eventos'][0]['comando'])
            self.assertIn(self.URL_A, expanded['mapeo']['eventos'][0]['comando'])
            quotes = app.state.tables['mapeo_mitre_evento']
            self.connection.execute(quotes.delete().where(quotes.c.id_mapeo==UUID(legacy['id_mapeo'])))
            historical = self.client.get('/api/mitre/resumen',params={**filters,'citas':'sin'}).json()
            self.assertEqual(historical['totales']['sin_citas'],1)
            self.assertEqual(historical['evolucion'][0]['origen_fecha'],'inicio_sesion')
        self.assertEqual(self.client.get('/api/mitre/tecnicas',params={'sesion':namespace}).json(),[])

    def test_observable_explorer_counts_priority_and_linked_sessions(self):
        self.assertEqual(self.client.get('/api/iocs/resumen').status_code,401)
        self.enroll(828)
        name = uuid4().hex
        records = [
            self.event(name,1,"cowrie.login.success",password="fixture-opaque",username="usuario-fixture"),
            self.event(name,2,input=f"wget '{self.URL_A}'"),
            self.event(name,3,input="dig @10.2.3.4 files.corp.local"),
            self.event(name,4,"cowrie.session.closed"),
            self.event(name+"-other",5,"cowrie.session.closed",src_ip="8.8.8.8"),
        ]
        accepted = self.ingest(records)['confirmaciones']
        ids = [row['id_evento'] for row in accepted]
        sid = self.session_id(ids[1])
        self.analyze_fixture(sid,AnalysisResult(resumen="Orden registrada en el señuelo",acciones=[
            Finding(tipo="descarga",descripcion="Intento registrado",confianza=0.8,eventos=[ids[1]],
                iocs=[IocProposal(tipo="URL",valor=self.URL_A,evento=ids[1])],
                mitre=[self.proposal("T1105","TA0011",[ids[1]])])]))
        ip, url = self.ioc_id(self.IP), self.ioc_id(self.URL_A)
        filters = {"sesion":name,"tipo":"IP","alcance":"privada","estado":"pendiente","evidencia":"verificable"}
        response = self.client.get('/api/iocs/resumen',params={**filters,"q":self.IP})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()["totales"],{"observables":1,"observaciones":4,"eventos":4,
                                                     "sesiones":1,"verificables":1,"con_mitre":0})
        ranked = self.client.get('/api/iocs/explorar',params={"sesion":name,"tipo":"IP","orden":"observaciones","limit":1})
        self.assertEqual(ranked.status_code,200,ranked.text)
        top, = ranked.json()
        self.assertEqual((top["id_ioc"],top["sesiones"],top["observaciones"]),(str(ip),1,4))
        self.assertNotEqual(self.client.get('/api/iocs/explorar',params={
            "sesion":name, "tipo":"IP","orden":"observaciones","limit":1,"offset":1}).json()[0]["id_ioc"],str(ip))
        self.assertEqual(self.client.get('/api/iocs/resumen',params={"sesion":name,"hasta":"2001-01-01"}).json()["totales"]["observaciones"],0)
        self.assertEqual(self.client.get('/api/iocs/resumen',params={"desde":"2026-02-01","hasta":"2026-01-01"}).status_code,422)
        ip_profile = self.client.get(f'/api/iocs/{ip}/perfil')
        self.assertEqual(ip_profile.status_code,200,ip_profile.text)
        profile = ip_profile.json()
        self.assertEqual(profile["clasificacion"],{"version_ip":4,"alcance":"privada"})
        self.assertEqual(profile["comportamiento"]["autenticaciones_aceptadas"],1)
        self.assertEqual(profile["comportamiento"]["usuarios_objetivo"],1)
        self.assertEqual(profile["comportamiento"]["ordenes_dns"],1)
        self.assertEqual(profile["enriquecimiento"]["resultados"],[])
        public_ip = self.client.get(f"/api/iocs/{self.ioc_id('8.8.8.8')}/perfil").json()
        self.assertEqual((public_ip["estado_revision"],public_ip["comportamiento"]["desconexiones"]),("pendiente",1))
        start = f'/api/iocs/{ip}/observaciones'
        priority = self.client.get(start,params={"vista_segura":True,"categoria":"prioritarias","orden_evidencia":"relevancia"}).json()
        self.assertNotIn(str(ids[3]),{row["id_evento"] for row in priority})
        exact, = self.client.get(start,params={"vista_segura":True,"categoria":"prioritarias","id_evento":ids[3]}).json()
        self.assertEqual(exact["estado_revision"],"pendiente")
        self.assertNotIn("fixture-opaque",str(priority))
        matched, = self.client.get('/api/iocs/explorar',params={"sesion":name,"tecnica":"T1105","tactica":"TA0011"}).json()
        self.assertEqual((matched["id_ioc"],matched["tecnicas"]),(str(url),1))
        self.assertEqual(matched["valor"], self.URL_A)
        sessions = self.client.get(f'/api/iocs/{url}/sesiones')
        self.assertEqual(sessions.status_code,200,sessions.text)
        related, = sessions.json()
        self.assertEqual((related["id_sesion"],related["eventos"],related["observaciones"],related["tecnicas"]),
                         (str(sid),4,1,["T1105"]))
        revision = f"/api/inteligencia/observacion_ioc/{exact['id_observacion']}/revision"
        expected = self.client.get(revision).json()["revision"]
        self.assertEqual(self.client.patch(revision, json={"estado":"confirmado", "revision_esperada":expected,
                         "motivo":"Un analista no puede confirmar evidencia"}).status_code,403)

    def test_matrix_counts_each_historical_pair_only_once(self):
        self.enroll(827)
        name = uuid4().hex
        eid = self.ingest([self.event(name,1,input='uname -a')])['confirmaciones'][0]['id_evento']
        aid = self.analyze_fixture(self.session_id(eid), AnalysisResult(resumen='Consulta del entorno',acciones=[
            Finding(tipo='consulta',descripcion='Entrada registrada',confianza=0.8,eventos=[eid],
                    mitre=[self.proposal('T1082','TA0007',[eid])])]))
        tables = app.state.tables
        actions, links, mappings = (tables[key] for key in ('accion_identificada','tecnica_tactica','mapeo_mitre'))
        action = self.connection.scalar(select(actions.c.id_accion).where(actions.c.id_analisis==UUID(aid)))
        pairs = list(self.connection.scalars(select(links.c.id_vinculo).where(
            links.c.codigo_tecnica=='T1053.003', links.c.codigo_tactica.in_(('TA0003','TA0004')))))
        self.assertEqual(len(pairs),2)
        self.connection.execute(mappings.insert(),[
            {'id_accion':action,'id_vinculo':pair,'evidencia':'Registro histórico sin cita',
             'justificacion':'Dato de prueba histórico'} for pair in pairs])
        params = {'sesion':name,'codigo':'T1053.003'}
        rows = self.client.get('/api/mitre/matriz',params=params).json()
        self.assertEqual({row['codigo_tactica']:row['mapeos'] for row in rows},{'TA0003':1,'TA0004':1})
        summary = self.client.get('/api/mitre/resumen',params=params).json()['totales']
        self.assertEqual((summary['tecnicas'],summary['tacticas'],summary['sesiones'],summary['mapeos']),(1,2,1,2))
        self.assertEqual(summary['pendientes'],2)

    def test_cowrie_order_url_equality_cross_session_file_and_replay(self):
        self.enroll(811)
        one, two = uuid4().hex, uuid4().hex
        rows = [
            self.event(one, 5, "cowrie.session.file_download", url=self.URL_A, shasum=self.DIGEST),
            self.event(one, 1, input=f"curl '{self.URL_A}'"),
            self.event(one, 2, input=f"wget '{self.URL_B}'"),
            self.event(one, 3, "cowrie.session.file_download", url=self.URL_C),
            self.event(two, 4, input=f"wget '{self.URL_A}'"),
        ]
        result = self.ingest(rows)
        completion, attempt, different, no_command, unrelated = [r["id_evento"] for r in result["confirmaciones"]]
        found = self.observations(self.URL_A)
        actual = self.validate_relation(found[completion], "comando_transferencia", "contextual")
        self.assertEqual([ref["id_evento"] for ref in actual["eventos"]], [str(completion), str(attempt)])
        self.assertLess(actual["eventos"][0]["numero_secuencia"], actual["eventos"][1]["numero_secuencia"])
        self.assertGreater(datetime.fromisoformat(actual["eventos"][0]["fecha_hora"]),
                           datetime.fromisoformat(actual["eventos"][1]["fecha_hora"]))
        self.assertNotEqual(actual["eventos"][0]["fecha_hora"], actual["eventos"][0]["ingresado_en"])
        self.validate_relation(found[attempt], "comando_transferencia", "contextual")
        self.validate_relation(found[unrelated], "comando_transferencia", "insuficiente")
        self.validate_relation(self.observations(self.URL_B)[different], "comando_transferencia", "insuficiente")
        self.validate_relation(self.observations(self.URL_C)[no_command], "comando_transferencia", "insuficiente")
        direct = self.validate_relation(found[completion], "url_archivo", "directa")
        self.assertEqual(direct["observable"]["valor"], self.DIGEST.lower())
        reverse = self.validate_relation(self.observations(self.DIGEST.lower())[completion], "url_archivo", "directa")
        self.assertEqual(reverse["observable"]["valor"], self.URL_A)
        private_ip = self.client.get("/api/iocs", params={"id_ioc": str(self.ioc_id(self.IP))}).json()[0]
        self.assertEqual((private_ip["sesiones"], private_ip["evidencias"]), (2, 5))
        replay = self.ingest(rows)
        self.assertEqual((replay["insertados"], replay["duplicados"]), (0, 5))
        self.assertEqual(self.observations(self.URL_A), found)
        with patch.object(app.state, "ioc_transfer_window", 3):
            self.validate_relation(self.observations(self.URL_A)[completion], "comando_transferencia", "insuficiente")
        session = self.session_id(completion)
        endpoint = f"/api/sesiones/{session}/eventos"
        self.assertEqual(self.client.get(endpoint, params={"id_evento": completion}).json()[0]["id_evento_texto"], str(completion))
        self.assertEqual(self.client.get(endpoint, params={"id_evento": unrelated}).json(), [])

    def test_late_second_command_makes_existing_match_ambiguous(self):
        self.enroll(812)
        session = uuid4().hex
        first = self.event(session, 0, input=f"wget '{self.URL_A}'")
        failed = self.event(session, 3, "cowrie.session.file_download.failed", url=self.URL_A)
        result = self.ingest([first, failed])
        first_id, failure_id = [r["id_evento"] for r in result["confirmaciones"]]
        self.validate_relation(self.observations(self.URL_A)[failure_id], "comando_transferencia", "contextual")
        later_import = self.event(session, 1, input=f"curl '{self.URL_A}'")
        second_id = self.ingest([later_import])["confirmaciones"][0]["id_evento"]
        found = self.observations(self.URL_A)
        ambiguous = self.validate_relation(found[failure_id], "comando_transferencia", "candidata")
        self.assertEqual(ambiguous["total_candidatos"], 2)
        self.assertEqual([ref["id_evento"] for ref in ambiguous["eventos"]], list(map(str, (failure_id, first_id, second_id))))
        self.assertEqual(ambiguous["eventos"][0]["rol"], "descarga_fallida")
        self.validate_relation(found[first_id], "comando_transferencia", "candidata")

    def test_mitre_requires_exact_citation_and_compatible_observable_and_keeps_review(self):
        self.enroll(813, admin=True)
        session = uuid4().hex
        rows = [
            self.event(session, 1, input=f"wget '{self.URL_A}'"),
            self.event(session, 2, input=f"curl '{self.URL_B}'"),
            self.event(session, 3, input="uname -a"),
        ]
        a, b, uname = [r["id_evento"] for r in self.ingest(rows)["confirmaciones"]]
        session_id = self.session_id(a)
        findings = [
            Finding(tipo="comandos registrados", descripcion="Secuencia registrada por Cowrie", confianza=0.8,
                eventos=[a, b, uname], iocs=[IocProposal(tipo="URL", valor=self.URL_A, evento=a),
                    IocProposal(tipo="URL", valor=self.URL_B, evento=b), IocProposal(tipo="IP", valor=self.IP, evento=a)],
                mitre=[self.proposal("T1105", "TA0011", [a]), self.proposal("T1082", "TA0007", [uname])]),
            Finding(tipo="shell", descripcion="Mapeo con evidencia heredada de la acción", confianza=0.8,
                eventos=[a], iocs=[IocProposal(tipo="URL", valor=self.URL_A, evento=a)],
                mitre=[self.proposal("T1059.004", "TA0002", [])]),
        ]
        aid = self.analyze_fixture(session_id, AnalysisResult(resumen="Escenario de laboratorio", acciones=findings))
        analysis_path = f"/api/analisis/{aid}"
        analysis = self.client.get(analysis_path).json()
        all_maps = {m["codigo_tecnica"]: m for entry in analysis["acciones"] for m in entry["mitre"]}
        transfer = all_maps["T1105"]
        self.assertEqual([(x["id_evento"],x["metodo"]) for x in transfer["eventos"]], [(str(a),"rag_validado_v1")])
        self.assertNotIn("T1059.004", all_maps)
        b_link, = self.observations(self.URL_B)[b]["acciones"]
        self.assertEqual((b_link["estado"], b_link["tecnicas"]), ("directa", []))
        ip_link, = self.observations(self.IP)[a]["acciones"]
        self.assertEqual(ip_link["tecnicas"], [])
        action = next(entry for entry in analysis["acciones"] if entry["tipo_accion"] == "comandos registrados")
        self.assertEqual({item["valor"] for item in action["observables"]}, {self.URL_A, self.URL_B, self.IP})
        endpoint = f"/api/mitre/mapeos/{all_maps['T1082']['id_mapeo']}/observables"
        self.assertEqual(self.client.get(endpoint).json()["observables"], [])
        mid = transfer["id_mapeo"]
        endpoint = f"/api/mitre/mapeos/{mid}/observables"

        def assert_relation(review, state):
            associations = self.observations(self.URL_A)[a]["acciones"]
            pair, = [item for association in associations for item in association["tecnicas"]]
            self.assertEqual((pair["estado_revision"], pair["estado"], pair["evento_compartido"]), (review, state, str(a)))
            reverse = self.client.get(endpoint).json()
            self.assertEqual(reverse["mapeo"]["estado_revision"], review)
            if review == "descartado":
                self.assertEqual(reverse["observables"], [])
            else:
                observable, = reverse["observables"]
                self.assertEqual((observable["valor"],observable["estado"]), (self.URL_A,state))

        assert_relation("pendiente","contextual")
        revision = f"/api/inteligencia/mitre/{mid}/revision"
        decision = {"estado":"confirmado", "motivo":"Decisión documentada de la revisión"}
        self.assertEqual(self.client.patch(revision, json=decision).status_code, 422)
        expected = self.client.get(revision).json()["revision"]
        self.assertIsNone(expected)
        for review,state in (("confirmado","contextual"),("descartado","insuficiente")):
            if review == "descartado":
                stale = self.client.patch(revision, json={**decision, "estado":review, "revision_esperada":None})
                self.assertEqual(stale.status_code, 409, stale.text)
                assert_relation("confirmado", "contextual")
            response = self.client.patch(revision, json={**decision, "estado":review, "revision_esperada":expected})
            self.assertEqual(response.status_code, 200, response.text)
            assert_relation(review,state)
            expected = response.json()["revision"]
        self.assertEqual(self.client.get(analysis_path).json()["resultado_estructurado"], analysis["resultado_estructurado"])
        with patch("backend.routes.real_result", side_effect=AssertionError("Análisis completado")):
            self.assertTrue(self.client.post(f"/api/sesiones/{session_id}/analizar").json()["reutilizado"])
        link = app.state.tables["mapeo_mitre_evento"]
        self.assertEqual(self.connection.scalar(select(func.count()).where(link.c.id_mapeo == UUID(mid))), 1)
        different_action = next(entry['id_accion'] for entry in analysis['acciones'] if entry['tipo_accion']=='shell')
        with self.assertRaises(IntegrityError), self.connection.begin_nested():
            self.connection.execute(link.insert().values(id_mapeo=all_maps["T1082"]["id_mapeo"],
                id_accion=different_action, id_evento=a, metodo="rag_validado_v1"))

    def test_migration_recovers_only_complete_historical_citations_and_preserves_original_rows(self):
        self.enroll(814, admin=True)
        sensor_session = uuid4().hex
        events = [self.event(sensor_session, 0, input=f"wget '{self.URL_A}'"),
                  self.event(uuid4().hex, 1, input="uname -a")]
        a, foreign = [r["id_evento"] for r in self.ingest(events)["confirmaciones"]]
        aid = self.analyze_fixture(self.session_id(a), AnalysisResult(resumen="Escenario histórico", acciones=[
            Finding(tipo=kind, descripcion="Intento registrado", confianza=0.8, eventos=[a],
                iocs=[IocProposal(tipo="URL", valor=self.URL_A, evento=a)], mitre=[self.proposal("T1105","TA0011",[a])])
            for kind in ("cita íntegra", "cita ajena")
        ]))
        citations, mappings = (app.state.tables[key] for key in ("mapeo_mitre_evento","mapeo_mitre"))
        ids = {}
        for action in self.client.get(f"/api/analisis/{aid}").json()["acciones"]:
            mapping, = action["mitre"]
            mid = UUID(mapping["id_mapeo"])
            ids[action["tipo_accion"]] = mid
            self.connection.execute(citations.delete().where(citations.c.id_mapeo == mid))
            data = {key: value for key, value in mapping["rag_procedencia"].items() if key not in {"citas_explicitas","clasificacion"}}
            if action["tipo_accion"] == "cita ajena":
                data["eventos"] = [a, foreign]
            self.connection.execute(mappings.update().where(mappings.c.id_mapeo == mid).values(rag_procedencia=data))
        report=self.client.get(f'/api/sesiones/{self.session_id(a)}/informe?id_analisis={aid}').json()
        historical=next(section for section in report['sections'] if section['title']=='Mapeos MITRE ATT&CK')
        self.assertEqual([row[3] for row in historical['rows']],['Sin citas verificables']*2)
        snapshot = lambda: self.connection.execute(select(mappings).where(
            mappings.c.id_mapeo.in_(ids.values())).order_by(mappings.c.id_mapeo)).all()
        original = snapshot()
        script = Path("database/migrations/011_correlacion_ioc_mitre.sql").read_text(encoding="utf-8")
        for _ in range(2):
            self.connection.connection.driver_connection.execute(script, prepare=False)
            actual = self.connection.execute(select(citations.c.id_mapeo, citations.c.id_evento, citations.c.metodo)
                .where(citations.c.id_mapeo.in_(ids.values()))).all()
            self.assertEqual(actual, [(ids["cita íntegra"], a, "cita_rag_historica_v1")])
            self.assertEqual(snapshot(), original)

    def test_authorized_read_and_admin_review_are_separate(self):
        anonymous = self.client.get(f"/api/mitre/mapeos/{uuid4()}/observables")
        self.assertEqual(anonymous.status_code, 401)
        self.assertEqual(self.client.get(f"/api/iocs/{uuid4()}/observaciones").status_code, 401)
        self.assertEqual(self.client.get("/api/mitre/resumen").status_code, 401)
        self.assertEqual(self.client.get("/api/mitre/matriz").status_code, 401)
        self.assertEqual(self.client.get("/api/mitre/tecnicas/T1105").status_code, 401)
        self.enroll(815)
        eid = self.ingest([self.event(uuid4().hex,1,input=f"wget '{self.URL_A}'")])['confirmaciones'][0]['id_evento']
        self.analyze_fixture(self.session_id(eid), AnalysisResult(resumen='Intento observado en Cowrie',acciones=[
            Finding(tipo='descarga',descripcion='Comando de descarga observado',confianza=0.8,eventos=[eid],
                    mitre=[self.proposal('T1105','TA0011',[eid])])]))
        self.assertEqual(self.client.get("/api/mitre/resumen").status_code, 200)
        mapping, = self.client.get("/api/mitre/mapeos", params={"id_sesion":str(self.session_id(eid))}).json()
        endpoint = f"/api/mitre/mapeos/{mapping['id_mapeo']}/observables"
        self.assertEqual(self.client.get(endpoint).status_code, 200)
        self.assertEqual(self.client.get(f"/api/mitre/mapeos/{uuid4()}/observables").status_code, 404)
        revision = f"/api/inteligencia/mitre/{mapping['id_mapeo']}/revision"
        version = self.client.get(revision).json()["revision"]
        denied = self.client.patch(revision, json={
            "estado": "confirmado", "motivo": "Intento de editar como analista", "revision_esperada":version})
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(self.client.get(endpoint).json()["mapeo"]["estado_revision"], mapping["estado_revision"])
