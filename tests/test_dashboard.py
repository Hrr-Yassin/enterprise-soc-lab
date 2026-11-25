from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from dashboard import AGENTS_URL, capture_agents


class NativeAgentCaptureTests(unittest.TestCase):
    def test_capture_requires_expected_active_endpoint_and_masks_addresses(self):
        page = Mock()
        tables, headings = Mock(), Mock()
        page.get_by_role.side_effect = lambda role, **_: {"table": tables, "columnheader": headings}[role]
        name = page.get_by_text.return_value
        table = tables.filter.return_value
        rows = table.locator.return_value
        row, other_agents = Mock(), Mock()
        rows.filter.side_effect = [row, other_agents]
        agent_id, status = Mock(), Mock()
        row.get_by_text.side_effect = [agent_id, status]
        table.get_by_role.return_value.evaluate.return_value = 2
        output = Path("/tmp/capture-fixture")

        capture_agents(page, {"name": "soc-linux", "id": "001"}, output)

        page.goto.assert_called_once_with(AGENTS_URL, wait_until="domcontentloaded", timeout=20000)
        page.get_by_text.assert_called_once_with("soc-linux", exact=True)
        table.locator.assert_called_once_with("tbody tr")
        rows.filter.assert_any_call(has=name)
        rows.filter.assert_any_call(has_not=name)
        row.get_by_text.assert_any_call("001", exact=True)
        self.assertIsNotNone(row.get_by_text.call_args.args[0].fullmatch("Active"))
        agent_id.wait_for.assert_called_once()
        status.wait_for.assert_called_once()
        row.locator.assert_called_once_with("td")
        row.locator.return_value.nth.assert_called_once_with(2)
        table.screenshot.assert_called_once_with(
            path=output / "soc-agents.png", animations="disabled",
            mask=[row.locator.return_value.nth.return_value, other_agents],
            mask_color="#28384b",
        )
