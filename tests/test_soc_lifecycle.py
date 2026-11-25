"""Exercise rule reload orchestration against disposable Podman responses."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

PODMAN_STUB = r'''#!/bin/bash
set -eu
test ! -e "/proc/$$/fd/9"
case "$1 $2" in
    "info --format") echo true ;;
    "container exists") exit 0 ;;
    "container inspect") echo enterprise-soc-lab ;;
    "exec -i")
        cat > "$SOC_TEST_ROOT/validated"
        if [[ "$SOC_TEST_MODE" == rejected ]]; then exit 42; fi
        printf 'New worktree edit\n' > "$SOC_TEST_ROOT/detections/rules.xml"
        ;;
    "restart enterprise-soc-manager")
        cat "$SOC_TEST_ROOT/restricted/wazuh/native/manager/etc/rules/enterprise_soc.xml" >> "$SOC_TEST_ROOT/restarts"
        if [[ "$SOC_TEST_MODE" == restart-fails ]] && grep -qx candidate "$SOC_TEST_ROOT/restarts" &&
            [[ $(wc -l < "$SOC_TEST_ROOT/restarts") == 1 ]]; then exit 43; fi
        ;;
    *) exit 99 ;;
esac
'''


class ReloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.script = self.root / "scripts/soc.sh"
        source = self.root / "detections/rules.xml"
        self.deployed = self.root / "restricted/wazuh/native/manager/etc/rules/enterprise_soc.xml"
        for path in (self.script, source, self.deployed):
            path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "scripts/soc.sh", self.script)
        source.write_text("candidate\n")
        self.deployed.write_text("prior\n")
        self.podman = self.root / "podman-stub"
        self.podman.write_text(PODMAN_STUB)
        self.podman.chmod(0o700)

    def reload(self, mode):
        return subprocess.run(
            ["bash", self.script, "reload-rules"], timeout=10, text=True, capture_output=True,
            env={**os.environ, "SOC_PODMAN": str(self.podman),
                 "SOC_TEST_ROOT": str(self.root), "SOC_TEST_MODE": mode},
        )

    def test_rejected_config_leaves_previous_rules_and_skips_restart(self):
        result = self.reload("rejected")
        self.assertEqual(result.returncode, 42)
        self.assertEqual(self.deployed.read_text(), "prior\n")
        self.assertFalse((self.root / "restarts").exists())

    def test_reload_publishes_the_validated_snapshot(self):
        result = self.reload("successful")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.deployed.read_text(), (self.root / "validated").read_text())
        self.assertEqual((self.root / "restarts").read_text(), "candidate\n")

    def test_failed_restart_restores_previous_rules_and_attempts_recovery(self):
        result = self.reload("restart-fails")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.deployed.read_text(), "prior\n")
        self.assertEqual((self.root / "restarts").read_text(), "candidate\nprior\n")
        self.assertIn("Previous rules restored", result.stderr)
