"""Contract regressions with inert fixture strings and independently stated expectations."""

from pathlib import Path
from unittest import TestCase

from backend.rag.mitre_evidence import CONTRACTS, KNOWN_MODES, technique_evidence
from backend.rag.pipeline import evidence_sample, facts_for_model
from backend.rag.retrieval import select_candidates
from backend.rag.validation import validate
from scripts.inventory_mitre import inventory
from test_rag import event, local_context, proposal, result


# The expected codes and exclusions are explicit fixture labels.
COMMAND_CASES = (
    ("T1007","TA0007","systemctl list-units --type=service","systemctl list-units --type=timer"),
    ("T1049","TA0007","ss -tn","ss --help"),
    ("T1069","TA0007","groups","groups --help"),
    ("T1069.001","TA0007","getent -s files group","getent group"),
    ("T1087.001","TA0007","cat /etc/passwd","cat ./passwd"),
    ("T1120","TA0007","lsusb -t","lsusb --version"),
    ("T1124","TA0007","timedatectl status","timedatectl --help"),
    ("T1201","TA0007","chage -l sample","chage --help"),
    ("T1518","TA0007","dpkg-query -W","dpkg-query --help"),
    ("T1518.001","TA0007","systemctl is-active auditd.service","systemctl is-active sample.service"),
    ("T1518.002","TA0007","systemctl is-active restic.service","systemctl is-active sample.service"),
    ("T1614.001","TA0007","localectl status","localectl --help"),
    ("T1652","TA0007","cat /proc/modules","cat ./modules"),
    ("T1654","TA0007","journalctl --list-boots","journalctl --help"),
    ("T1673","TA0007","systemd-detect-virt --vm","systemd-detect-virt --container"),
    ("T1680","TA0007","lsblk -f","lsblk --version"),
    ("T1016.002","TA0007","iw dev","iw help"),
    ("T1016.001","TA0007","nmcli networking connectivity check","nmcli networking off"),
    ("T1135","TA0007","showmount -e sample.example.org","showmount --help"),
    ("T1059.001","TA0002","pwsh -Command 'Write-Output sample'","pwsh --version"),
    ("T1059.006","TA0002","python3 -c 'print(1)'","python3 -V"),
    ("T1059.007","TA0002","node -e '1+1'","node --version"),
    ("T1059.011","TA0002","lua -e 'print(1)'","lua -v"),
    ("T1053.002","TA0002","at -f /tmp/fixture 14:00","at -f /tmp/fixture 28:61"),
    ("T1053.006","TA0003","systemctl enable sample.timer","systemctl enable sample.service"),
    ("T1098.007","TA0003","usermod -aG adm sample","usermod -aG users sample"),
    ("T1003.008","TA0006","cat /etc/shadow","cat /etc/passwd"),
    ("T1552.004","TA0006","cat /home/sample/.ssh/id_rsa","cat /home/sample/.ssh/id_rsa.pub"),
    ("T1552.003","TA0006","grep -i password /home/sample/.bash_history","grep -i nightly /home/sample/.bash_history"),
    ("T1040","TA0007","tcpdump -i sample0 -w /tmp/fixture.pcap","tcpdump -D"),
    ("T1222.002","TA0112","chmod 0600 /etc/shadow","chmod 0600 /tmp/fixture"),
    ("T1690","TA0112","set +o history","set -o history"),
    ("T1685.006","TA0112","truncate -s 0 /var/log/auth.log","truncate -s 0 /tmp/fixture.log"),
    ("T1489","TA0040","systemctl stop sample.service","systemctl status sample.service"),
    ("T1529","TA0040","systemctl reboot","systemctl --help"),
    ("T1531","TA0040","usermod --expiredate 1 sample","usermod --expiredate -1 sample"),
)


def checked(mode, code, tactic, events, citations, grade="intento", delivered=None):
    context = local_context(events, code, code, tactic)
    context["modalidad"] = mode
    selected = events if delivered is None else [entry for entry in events if entry.id_evento in delivered]
    context["eventos_entregados"] = [entry.id_evento for entry in selected]
    analysis = result(selected, [proposal(code, tactic, eventos=citations, grado_evidencia=grade)])
    rejected, provenance = validate(analysis, events, context)
    return analysis.acciones[0].mitre, rejected, provenance


class EvidenceModalityTests(TestCase):
    def test_persisted_command_shapes_remain_attempts_in_every_modality(self):
        # Exact command variants counted in PostgreSQL. Identifiers and metadata are synthetic.
        forms = (
            ("T1082","hostname",("hostname sample-name","hostname -I")),
            ("T1082","uptime",("uptime --help","echo uptime")),
            ("T1057","top -b -n 1",("top -h","top -b -n 1 -p 123")),
        )
        for mode in (*sorted(KNOWN_MODES), "desconocido"):
            for code, observed_input, exclusions in forms:
                with self.subTest(code=code, mode=mode, entry=observed_input):
                    raw = {"eventid": "cowrie.command.input", "session":"fixture",
                           "uuid":"431a49ee-9227-4a56-b744-b7ea3be5e118",
                           "timestamp":"2026-11-16T00:00:01Z", "protocol":"ssh", "dst_port":2222}
                    record = event(1,observed_input,**raw)
                    accepted, _, _ = checked(mode,code,"TA0007",[record],[1])
                    self.assertEqual(accepted[0].grado_evidencia,"intento")
                    self.assertFalse(checked(mode,code,"TA0007",[record],[1],grade="resultado_en_honeypot")[0])
                    for alternate in exclusions:
                        self.assertNotIn(code, technique_evidence([event(1,alternate,**raw)], mode))
                    self.assertFalse(technique_evidence([event(1,observed_input,kind="cowrie.command.failed")],mode))
                    self.assertFalse(technique_evidence([event(1,observed_input,realm="passwd",**raw)],mode))

    def test_each_new_command_in_each_registered_modality(self):
        for code, tactic, command, negative in COMMAND_CASES:
            for mode in sorted(KNOWN_MODES):
                with self.subTest(code=code, mode=mode):
                    records = [event(1, command), event(2, negative)]
                    accepted, rejected, entries = checked(mode, code, tactic, records, [1])
                    self.assertFalse(rejected)
                    self.assertEqual(accepted[0].eventos, [1])
                    self.assertEqual(accepted[0].grado_evidencia, "intento")
                    self.assertEqual(entries[(0, code, tactic)]["modalidad"], mode)
                    self.assertIn("anfitrión" if mode != "cowrie_llm" else "respuesta generada",
                                  entries[(0, code, tactic)]["alcance_sensor"])
                    for refs in ([], [2], [123], [1, 2]):
                        self.assertFalse(checked(mode,code,tactic,records,refs)[0])
                    self.assertFalse(checked(mode,code,"TA0043",records,[1])[0])
                    self.assertFalse(checked(mode,code,tactic,records,[1],grade="resultado_en_honeypot")[0])
                    for record in (event(1,command,realm="fixture-stdin"), event(1,command,kind="cowrie.command.success"),
                                   event(1,"echo " + command), event(1,command + "; pwd")):
                        self.assertFalse(checked(mode,code,tactic,[record],[1])[0])
            self.assertEqual(checked("desconocido",code,tactic,[event(1,command)],[1])[1][0]["causa"],
                             "modalidad_incompatible")

    def test_output_is_never_read_as_client_command_or_sent_as_prompt_content(self):
        marker = "INSTRUCCION_GENERADA_NO_CONFIABLE"
        events = [
            event(1,"cat /etc/shadow",kind="cowrie.llm.response",output=marker,message=marker,url=marker),
            event(2,"cat /etc/shadow",realm="passwd"),
            event(3,"cat /etc/shadow",kind="cowrie.proxy.ssh",payload=marker),
        ]
        for mode in KNOWN_MODES:
            self.assertFalse(technique_evidence(events, mode))
        self.assertNotIn(marker, str(facts_for_model(events)))
        self.assertNotIn("cat /etc/shadow", str(facts_for_model(events)))

    def test_sequences_require_same_target_session_order_and_window(self):
        fixtures = (
            ("T1560.001","TA0009","cat /etc/shadow","tar -cf /tmp/fixture.tar /etc/shadow",
             "tar -cf /tmp/fixture.tar /home/sample/.ssh/id_rsa"),
            ("T1543.002","TA0003","systemctl link /tmp/fixture.service","systemctl enable fixture.service",
             "systemctl enable other.service"),
        )
        for mode in KNOWN_MODES:
            for code, tactic, start, finish, wrong in fixtures:
                with self.subTest(mode=mode, code=code):
                    first, last = event(1,start,session="same"), event(2,finish,session="same")
                    accepted, _, _ = checked(mode,code,tactic,[first,last],[2,1])
                    self.assertEqual(accepted[0].eventos, [1,2])
                    for follow_up in (event(2,wrong,session="same"), event(2,finish,session="other"),
                                      event(400,finish,session="same")):
                        self.assertFalse(checked(mode,code,tactic,[first,follow_up],[1,follow_up.id_evento])[0])
                    self.assertFalse(checked(mode,code,tactic,[first,last],[2])[0])
                    self.assertFalse(checked(mode,code,tactic,[event(1,finish),event(2,start)],[1,2])[0])
            intervening = [event(1,"systemctl link /tmp/fixture.service"),
                           event(2,"systemctl mask fixture.service"),event(3,"systemctl enable fixture.service")]
            accepted, rejected, _ = checked(mode,"T1543.002","TA0003",intervening,[1,3],delivered={1,3})
            self.assertFalse(accepted)
            self.assertEqual(rejected[0]["causa"],"evidencia_contradictoria")

    def test_authentication_patterns_and_official_parent_deduplication(self):
        guesses = [event(i,kind="cowrie.login.failed",src_ip="192.0.2.7",username="same",password=f"fixture-{i}")
                   for i in range(1,4)]
        spray = [event(i,kind="cowrie.login.failed",src_ip="192.0.2.7",username=f"sample-{i}",password="fixture")
                 for i in range(1,4)]
        for mode in KNOWN_MODES:
            self.assertIn("T1110.003",technique_evidence(spray,mode))
            self.assertNotIn("T1110.003",technique_evidence(spray[:2],mode))
            self.assertNotIn("T1110.003",technique_evidence(guesses,mode))
            self.assertNotIn("T1110.001",technique_evidence(spray,mode))
            context = local_context(guesses,"T1110","Brute Force","TA0006")
            context["modalidad"] = mode
            context["candidatos"].append({**context["candidatos"][0],
                "codigo_tecnica":"T1110.001", "tecnica_padre_id":"T1110"})
            analysis = result(guesses,[proposal(code,"TA0006",eventos=[1,2,3]) for code in ("T1110","T1110.001")])
            rejected, _ = validate(analysis,guesses,context)
            self.assertEqual([mapping.codigo for mapping in analysis.acciones[0].mitre],["T1110.001"])
            self.assertEqual(rejected[0]["causa"],"padre_redundante")
            parent_only = result(guesses,[proposal("T1110","TA0006",eventos=[1,2,3])])
            self.assertFalse(validate(parent_only,guesses,context)[0])
            self.assertEqual([mapping.codigo for mapping in parent_only.acciones[0].mitre],["T1110.001"])

    def test_ssh_forward_requests_remain_attempts(self):
        for mode in KNOWN_MODES:
            raw = event(1,kind="cowrie.direct-tcpip.request",protocol="ssh",dst_ip="192.0.2.7",dst_port=8080)
            self.assertEqual(technique_evidence([raw],mode)["T1572"],{1:"intento"})
            for change in ({"protocol":"telnet"}, {"dst_ip":"0.0.0.0"}, {"dst_port":0}, {"dst_port":"8080"}):
                altered = event(1,kind=raw.tipo_evento,**(raw.datos_originales | change | {"command":"fixture"}))
                self.assertNotIn("T1572",technique_evidence([altered],mode))

    def test_rag_limits_exploration_instead_of_supported_techniques(self):
        candidates = [{"codigo_tecnica":f"T{i:04}", "plataformas":["Linux"], "puntuacion_hibrida":i,
                       "observabilidad":"intento_evaluable" if i < 41 else "sin_contrato"} for i in range(60)]
        selected = select_candidates(candidates, limit=24)
        self.assertEqual(len(selected),41)
        self.assertTrue(all(row["observabilidad"] == "intento_evaluable" for row in selected))
        records = [event(i,"pwd") for i in range(1,145)]
        for i, (_, _, command, _) in enumerate(COMMAND_CASES,40):
            records[i] = event(i+1,command)
        sample = evidence_sample(records,"cowrie_llm")
        self.assertLessEqual(len(sample),80)
        self.assertEqual(technique_evidence(sample,"cowrie_llm").keys(),technique_evidence(records,"cowrie_llm").keys())

    def test_inventory_covers_every_official_object_and_registered_rule(self):
        summary,rows = inventory(Path(".local/rag/enterprise-attack-20.1.json"))
        self.assertEqual((len(rows),summary["objetos_vigentes"],len(summary["tacticas"])),(867,706,15))
        supported = {row["codigo"] for row in rows if any(
            decision["clasificacion_automatica"] for decision in row["modalidades"].values())}
        self.assertEqual(supported,set(CONTRACTS))
        self.assertFalse(any(decision["clasificacion_automatica"] for row in rows if not row["vigente"]
                             for decision in row["modalidades"].values()))
        self.assertTrue(any(row["fuentes_linux_oficiales"] for row in rows if row["codigo"] == "T1210"))
