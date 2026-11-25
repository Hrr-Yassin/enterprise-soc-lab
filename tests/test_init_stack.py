import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import init_stack


class RuntimeTests(unittest.TestCase):
    def test_credentials_are_private_and_reinitialization_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "restricted" / "wazuh"
            with patch.object(init_stack, "RUNTIME", runtime):
                init_stack.initialize()
                native = runtime / "native"
                self.assertEqual(native.stat().st_mode & 0o777, 0o700)
                for name in ("manager.env", "dashboard.env", "credentials.txt"):
                    self.assertEqual((native / name).stat().st_mode & 0o777, 0o600)
                env = dict(line.split("=", 1) for line in (native / "manager.env").read_text().splitlines())
                self.assertNotEqual(env["INDEXER_PASSWORD"], env["API_PASSWORD"])
                self.assertNotEqual(env["INDEXER_PASSWORD"], "SecretPassword")
                self.assertNotIn("kibanaro:", (native / "internal_users.yml").read_text())
                with self.assertRaises(FileExistsError):
                    init_stack.initialize()

    def test_service_tls_verifies_names_and_dashboard_loopback(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(init_stack, "RUNTIME", Path(directory)):
            previous = os.umask(0o077)
            try:
                init_stack.initialize()
                init_stack.certificates()
            finally:
                os.umask(previous)
            pki = Path(directory) / "native/pki"
            for flags, name in (
                (["-verify_hostname", "wazuh.indexer"], "wazuh.indexer"),
                (["-verify_hostname", "wazuh.manager"], "wazuh.manager"),
                (["-verify_ip", "127.0.0.1"], "wazuh.dashboard"),
            ):
                subprocess.run(["openssl", "verify", "-x509_strict", "-CAfile", pki / "ca.pem",
                                *flags, pki / f"{name}.pem"], check=True, capture_output=True)
            self.assertEqual((pki / "ca.key").stat().st_mode & 0o777, 0o600)

    def test_upstream_drift_is_rejected(self):
        with self.assertRaises(ValueError):
            init_stack.replace_once("one", "missing", "new")
        with self.assertRaises(ValueError):
            init_stack.replace_once("one one", "one", "new")
