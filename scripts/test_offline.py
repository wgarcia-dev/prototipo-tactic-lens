"""Run local tests with paid LLM calls and real SMTP explicitly blocked."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


def main():
    root=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(root/'tests'))
    suite=unittest.defaultTestLoader.discover(str(root/'tests'))
    with patch('backend.routes.httpx.post',side_effect=AssertionError('DeepSeek real bloqueado en pruebas')), \
         patch('smtplib.SMTP',side_effect=AssertionError('SMTP real bloqueado en pruebas')), \
         patch('smtplib.SMTP_SSL',side_effect=AssertionError('SMTP real bloqueado en pruebas')):
        result=unittest.TextTestRunner(verbosity=1).run(suite)
    raise SystemExit(not result.wasSuccessful())


if __name__=='__main__':main()
