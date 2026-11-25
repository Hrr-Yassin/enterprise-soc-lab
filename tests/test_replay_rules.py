import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import replay_rules


class ReplayCommandTests(unittest.TestCase):
    def test_command_fails_and_retains_all_results_when_one_fixture_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "run.json"
            report.write_text("{}\n")
            report.with_name("manager-archives.jsonl").write_text("")
            fixtures = []
            responses = []
            for case, (decoder, log_format) in replay_rules.CASES.items():
                rule = replay_rules.SCENARIOS[case][0]
                for phase in ("positive", "control"):
                    payload = {"event": "fixture", "location": "test", "log_format": log_format}
                    metadata = {"scenario": case, "phase": phase, "expected_decoder": decoder,
                                "target_rule": rule}
                    fixtures.append((payload, metadata))
                    matches = phase == "positive" and case != "D09"
                    output = {"decoder": {"name": decoder}}
                    if matches:
                        output["rule"] = {"id": rule}
                    responses.append({"error": 0, "data": {"output": output, "alert": matches}})

            with patch.object(sys, "argv", ["replay_rules.py", str(report)]), \
                    patch.object(replay_rules, "prepare", return_value=fixtures), \
                    patch.object(replay_rules.health, "api", side_effect=responses) as api, \
                    patch.object(replay_rules.os, "umask"), redirect_stdout(io.StringIO()):
                self.assertEqual(replay_rules.main(), 1)

            self.assertEqual(api.call_count, 6)
            evidence, = Path(directory).glob("wazuh-logtest-*.jsonl")
            results = [json.loads(line) for line in evidence.read_text().splitlines()]
            self.assertEqual(len(results), 6)
            self.assertEqual([(row["scenario"], row["phase"]) for row in results if not row["passed"]],
                             [("D09", "positive")])


if __name__ == "__main__":
    unittest.main()
