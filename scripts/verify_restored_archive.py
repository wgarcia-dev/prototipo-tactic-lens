"""Read-only comparison of historical row counts and encrypted MFA material."""
import json
from pathlib import Path
from dotenv import dotenv_values
from scripts.historical_database import ROOT, connect, inspect


def main():
    private = ROOT/'.local/restauracion'
    before = json.loads((private/'restore-result.json').read_text(encoding='utf-8'))
    expected = {}
    inside = False
    for line in (private/'archive-inspection.sql').read_text(encoding='utf-8').splitlines():
        if line.startswith('COPY honeypot.auth_factor '):
            inside = True
            continue
        if inside and line == r'\.':
            inside = False
            continue
        if inside:
            fields = line.split('\t')
            expected[fields[0]] = fields[1]
    with connect(dotenv_values(ROOT/'.env')) as conn:
        conn.execute('SET TRANSACTION READ ONLY')
        after = inspect(conn)
        actual = {str(user): encrypted for user, encrypted in conn.execute('SELECT id_usuario,secreto_cifrado FROM honeypot.auth_factor')}
        changes = {name: [count, after['counts'].get(name)] for name, count in before['counts'].items()
                   if after['counts'].get(name) != count}
        unvalidated = conn.execute("SELECT count(*) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='honeypot' AND NOT convalidated").fetchone()[0]
    report = dict(counts=after['counts'], changed_counts=changes, original_encrypted_mfa_preserved=actual == expected,
                  unvalidated_constraints=unvalidated)
    (private/'history-verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))
    if not report['original_encrypted_mfa_preserved'] or unvalidated:
        raise SystemExit('La verificación requiere revisión')


if __name__ == '__main__':
    main()
