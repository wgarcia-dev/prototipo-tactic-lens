import io,json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zipfile
from cryptography.fernet import Fernet,InvalidToken
from scripts.portability import canonical_constraint,constraints_equal,restore
from scripts.private_transfer import safe_member,pack,unpack
from scripts.recover_private import recover


class PortabilitySafetyTests(unittest.TestCase):
    def test_only_equivalent_varchar_array_casts_are_normalized(self):
        original="CHECK (estado = ANY ((ARRAY['pendiente'::character varying, 'activo'::character varying])::text[]))"
        restored="CHECK (estado = ANY (ARRAY[('pendiente'::character varying)::text, ('activo'::character varying)::text]))"
        self.assertEqual(canonical_constraint(original),restored)
        self.assertNotEqual(canonical_constraint(original),restored.replace('activo','bloqueado'))

    def test_fk_changes_or_validation_changes_still_fail(self):
        a={'definicion':'FOREIGN KEY (id) REFERENCES honeypot.evento(id_evento)','validada':True}
        self.assertTrue(constraints_equal([a],[a]))
        self.assertFalse(constraints_equal([a],[{**a,'validada':False}]))
        self.assertFalse(constraints_equal([a],[{**a,'definicion':a['definicion'].replace('evento','sesion')}]))

    def test_restore_rejects_maintenance_targets_before_database_access(self):
        with patch('scripts.portability.engine_for') as engine:
            for target in ('postgres','template0','template1','bad;DROP TABLE users'):
                with self.subTest(target=target),self.assertRaises(ValueError):restore('missing','missing',target)
            engine.assert_not_called()

    def test_archive_paths_cannot_escape_destination(self):
        for name in ('../escape','/absolute','C:/secret','a\\..\\escape'):
            with self.subTest(name=name),self.assertRaises(ValueError):safe_member(name)

    def fixture(self,root):
        (root/'.local/migration/job/database').mkdir(parents=True)
        (root/'.local/migration/job/database/test.backup').write_bytes(b'fixture-backup')
        (root/'.local/cache').mkdir();(root/'.local/cache/model.bin').write_bytes(b'fixture-model')
        (root/'frontend').mkdir();(root/'.env').write_text('AUTH_SECRET_KEY=fixture-only-never-real')

    def test_encrypted_roundtrip_authenticates_and_preserves_bytes(self):
        with TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root)
            token=root/'.local/migration/job/transfer.fernet';key=root/'.local/migration/job/transfer.key'
            with patch('scripts.private_transfer.ROOT',root):result=pack(root/'.local/migration/job',token,key)
            self.assertGreater(result['archivos'],2)
            self.assertNotIn(b'fixture-only-never-real',token.read_bytes())
            dest=root/'recovered';unpack(token.read_bytes(),key.read_bytes(),dest)
            self.assertEqual((dest/'config/.env').read_bytes(),(root/'.env').read_bytes())
            self.assertEqual((dest/'local-state/cache/model.bin').read_bytes(),b'fixture-model')
            with self.assertRaises(ValueError):unpack(token.read_bytes(),key.read_bytes(),dest)

    def test_tampered_encrypted_archive_writes_no_plaintext(self):
        with TemporaryDirectory() as temp:
            root=Path(temp);key=Fernet.generate_key();value=bytearray(Fernet(key).encrypt(b'test'));value[-8]^=1
            with self.assertRaises(InvalidToken):unpack(bytes(value),key,root/'out')
            self.assertFalse((root/'out').exists())

    def test_authenticated_zip_with_traversal_is_rejected(self):
        memory=io.BytesIO()
        with zipfile.ZipFile(memory,'w') as z:z.writestr('../escape','content')
        key=Fernet.generate_key()
        with TemporaryDirectory() as temp,self.assertRaises(ValueError):unpack(Fernet(key).encrypt(memory.getvalue()),key,Path(temp)/'out')

    def test_recovery_keeps_existing_private_configuration(self):
        with TemporaryDirectory() as temp:
            root=Path(temp);source=root/'received';(source/'config').mkdir(parents=True)
            (source/'config/.env').write_text('AUTH_SECRET_KEY=fixture-restored')
            (root/'.env.example').write_text('AUTH_SECRET_KEY=')
            (root/'.env').write_text('AUTH_SECRET_KEY=')
            result=recover(source,root);self.assertEqual(result['copiados'],1)
            self.assertEqual(recover(source,root)['copiados'],0)
            (root/'.env').write_text('AUTH_SECRET_KEY=fixture-already-private')
            with self.assertRaises(ValueError):recover(source,root)
            self.assertEqual((root/'.env').read_text(),'AUTH_SECRET_KEY=fixture-already-private')

    def test_relocated_backup_pointer_is_idempotent_even_inside_local_directory(self):
        with TemporaryDirectory() as temp:
            base=Path(temp);root=base/'.local/clone';root.mkdir(parents=True)
            source=base/'received';(source/'config').mkdir(parents=True)
            (source/'config/.env').write_text('AUTH_SECRET_KEY=fixture-restored')
            state=source/'local-state/rag';(state/'private').mkdir(parents=True)
            (state/'private/manifest.json').write_text('{}')
            (state/'backup-pointer.json').write_text(json.dumps({'manifest':'C:/old/.local/rag/private/manifest.json'}))
            recover(source,root)
            pointer=json.loads((root/'.local/rag/backup-pointer.json').read_text())['manifest']
            self.assertEqual(Path(pointer),root/'.local/rag/private/manifest.json')
            self.assertEqual(recover(source,root)['copiados'],0)
