import datetime as dt
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch
from xml.etree import ElementTree

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from replay_rules import evaluate
from run_scenarios import alerts, control_evidence, evaluate_scenario, event_matches

RUN = "1234abcd"
START = dt.datetime(2026, 11, 25, 12, 0, tzinfo=dt.timezone.utc)
POSITIVE_START = START + dt.timedelta(seconds=25)
RULES = ElementTree.parse(Path(__file__).resolve().parents[1] / "detections/rules.xml")


def systemd(phase, second, document, target=False):
    label = "sandbox" if phase == "positive" else "inventory"
    unit = f"soc-lab-{label}-{RUN}.service"
    action = {"scenario": "D05", "phase": phase, "unit": unit,
              "started": (POSITIVE_START if phase == "positive" else START).isoformat(),
              "finished": (POSITIVE_START if phase == "positive" else START).isoformat()}
    record = {"timestamp": (START + dt.timedelta(seconds=second)).isoformat(),
              "full_log": f"Started {unit} - SOC lab job {label}-{RUN}.",
              "document_id": document, "id": document}
    if phase == "positive" or target:
        record["rule"] = {"id": "100105"}
    return action, record


class EvidenceTests(unittest.TestCase):
    def test_late_control_target_alert_fails_scenario(self):
        control, late_alert = systemd("control", 28, "late-control", target=True)
        positive, positive_alert = systemd("positive", 27, "positive")
        result = evaluate_scenario(control, positive, [positive_alert, late_alert], [late_alert],
                                   RUN, POSITIVE_START, START + dt.timedelta(seconds=45))
        self.assertFalse(result["passed"])
        self.assertEqual(result["control_alert_ids"], ["late-control"])
        self.assertEqual(result["observed_alerts"], [positive_alert])

    def test_manager_target_match_fails_even_if_missing_from_index(self):
        control, archived = systemd("control", 2, "control")
        _, late_match = systemd("control", 36, "archive-only", target=True)
        positive, positive_alert = systemd("positive", 26, "positive")
        result = evaluate_scenario(control, positive, [positive_alert], [archived, late_match],
                                   RUN, POSITIVE_START, START + dt.timedelta(seconds=45))
        self.assertFalse(result["passed"])
        self.assertEqual(result["control_alert_ids"], [])
        self.assertEqual(result["control_evidence"]["manager_target_record_ids"], ["archive-only"])

    def test_unattributed_target_alert_cannot_pass(self):
        control, archived = systemd("control", 2, "control")
        positive, positive_alert = systemd("positive", 26, "positive")
        unknown = {**positive_alert, "full_log": "Unrelated service started.", "document_id": "unknown"}
        result = evaluate_scenario(control, positive, [positive_alert, unknown], [archived],
                                   RUN, POSITIVE_START, START + dt.timedelta(seconds=40))
        self.assertFalse(result["passed"])
        self.assertEqual(result["unexpected_target_alert_ids"], ["unknown"])

    def test_negative_control_requires_archive_receipt_and_index_settle(self):
        control, archived = systemd("control", 28, "control")
        positive, positive_alert = systemd("positive", 27, "positive")
        for seconds, archived_events, expected in [(40, [], False), (35, [archived], False), (40, [archived], True)]:
            with self.subTest(seconds=seconds, archived=bool(archived_events)):
                result = evaluate_scenario(control, positive, [positive_alert], archived_events,
                                           RUN, POSITIVE_START, START + dt.timedelta(seconds=seconds))
                self.assertEqual(result["passed"], expected)

    def test_ssh_receipt_counts_distinct_attempts(self):
        control = {"scenario": "D01", "phase": "control", "records": 7, "source_ip": "203.0.113.5",
                   "started": START.isoformat(), "finished": START.isoformat()}
        event = {"timestamp": START.isoformat(), "id": "archive-1",
                 "data": {"srcip": "203.0.113.5", "srcport": "25000", "dstuser": f"lab-{RUN}"}}
        result = control_evidence(control, [event] * 7, RUN)
        self.assertEqual(result["manager_records"], 1)
        self.assertEqual(result["expected_records"], 7)

    def test_policy_control_requires_same_run_watch_and_path(self):
        action = {"scenario": "D09", "phase": "control", "audited_control_path": "/var/lib/soc-lab/policy/control.conf"}
        title = f"/home/soc/exercise.py\0{RUN}\0control".encode().hex().upper()
        audit = {"type": "SYSCALL", "key": "soc_policy_control", "success": "yes",
                 "file": {"name": action["audited_control_path"]}}
        event = {"data": {"audit": audit}, "full_log": f"proctitle={title}"}
        self.assertTrue(event_matches(event, action, RUN))
        self.assertFalse(event_matches(event, action, "4321abcd"))
        audit["key"] = "soc_policy_change"
        self.assertFalse(event_matches(event, action, RUN))

    def test_sudo_run_marker_is_checked_in_hex_audit_command(self):
        action = {"scenario": "D03", "phase": "positive", "user": "soc-probe",
                  "command": f"/usr/bin/true soc-d03-{RUN}-positive"}
        command = action["command"].encode().hex().upper()
        event = {"data": {"audit": {"type": "USER_CMD", "exe": '"/usr/bin/sudo"', "res": "failed"}},
                 "full_log": f'cmd={command} exe="/usr/bin/sudo" res=failed\x1dUID="soc-probe"'}
        self.assertTrue(event_matches(event, action, RUN))
        self.assertFalse(event_matches(event, {**action, "command": "/usr/bin/true"}, RUN))

    def test_logtest_control_requires_decoding_even_without_target_rule(self):
        sample = {"scenario": "D03", "phase": "control", "expected_decoder": "auditd", "target_rule": "100103"}
        self.assertFalse(evaluate({"error": 0, "data": {"output": {}, "alert": False}}, sample)["passed"])
        self.assertTrue(evaluate(
            {"error": 0, "data": {"output": {"decoder": {"name": "auditd"}}, "alert": False}}, sample
        )["passed"])


class AlertQueryTests(unittest.TestCase):
    def test_complete_search_accepts_skipped_shards(self):
        hits = [{"_id": "synthetic-alert"}]
        response = {"timed_out": False, "_shards": {"total": 2, "successful": 2, "skipped": 1, "failed": 0},
                    "hits": {"total": {"value": len(hits)}, "hits": hits}}
        with patch("run_scenarios.health.indexer", return_value=response) as indexer:
            self.assertEqual(alerts("001", START), hits)
        self.assertIn("allow_partial_search_results=false", indexer.call_args.args[0])

    def test_incomplete_search_cannot_supply_alert_evidence(self):
        for timed_out, successful, failed in [(True, 2, 0), (False, 1, 1), (False, 1, 0)]:
            with self.subTest(timed_out=timed_out, successful=successful, failed=failed):
                response = {"timed_out": timed_out, "_shards": {"total": 2, "successful": successful, "failed": failed}}
                with patch("run_scenarios.health.indexer", return_value=response):
                    with self.assertRaisesRegex(RuntimeError, "Incomplete indexer search"):
                        alerts("001", START)


class RulePredicateTests(unittest.TestCase):
    # These assertions model the archived inputs of the XML predicates.
    # The authorized Wazuh Logtest replay covers decoder and rule-tree behavior.
    def field_match(self, rule_id, fields, parent="80700"):
        rule = RULES.find(f"./rule[@id='{rule_id}']")
        self.assertEqual(rule.findtext("if_sid"), parent)
        return all(re.fullmatch(field.text, fields.get(field.get("name"), "")) is not None
                   for field in rule.findall("field"))

    def test_sudo_rule_requires_a_failed_user_cmd_from_sudo(self):
        fields = {"audit.type": "USER_CMD", "audit.exe": '"/usr/bin/sudo"', "audit.res": "failed"}
        self.assertTrue(self.field_match("100103", fields))
        self.assertFalse(self.field_match("100103", {**fields, "audit.res": "success"}))
        self.assertFalse(self.field_match("100103", {**fields, "audit.type": "USER_ERR"}))

    def test_systemd_rule_checks_the_unit_and_job_policy(self):
        match = RULES.findtext("./rule[@id='100105']/match")
        label = f"sandbox-{RUN}"
        positive = f"Started soc-lab-{label}.service - SOC lab job {label}."
        self.assertIsNotNone(re.fullmatch(match, positive))
        for control in (positive.replace("sandbox", "inventory"),
                        positive.replace("soc-lab-sandbox", "soc-lab-inventory"),
                        positive.replace("Started", "Starting")):
            self.assertIsNone(re.fullmatch(match, control))

    def test_policy_rule_requires_target_path_key_and_outcome(self):
        fields = {"audit.type": "SYSCALL", "audit.key": "soc_policy_change", "audit.success": "yes",
                  "audit.file.name": "/var/lib/soc-lab/policy/service.conf"}
        parent = "80700,92600"
        self.assertTrue(self.field_match("100109", fields, parent))
        self.assertFalse(self.field_match("100109", {**fields, "audit.key": "soc_policy_control"}, parent))
        self.assertFalse(self.field_match(
            "100109", {**fields, "audit.file.name": "/var/lib/soc-lab/policy/control.conf"}, parent
        ))
        self.assertFalse(self.field_match("100109", {**fields, "audit.success": "no"}, parent))


if __name__ == "__main__":
    unittest.main()
