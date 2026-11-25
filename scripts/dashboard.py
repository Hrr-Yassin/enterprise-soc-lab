#!/usr/bin/env python3
"""Import the SOC saved objects and capture the actual Wazuh dashboard."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import health

BASE = "https://127.0.0.1:8443"
DATA_VIEW = "enterprise-soc-alerts"
DASHBOARD = "enterprise-soc-operations"
AGENTS_URL = BASE + "/app/endpoints-summary#/agents-preview/"
VERSION = "2.19.6"


def saved(object_id, kind, attributes, references=()):
    return {"id": object_id, "type": kind, "attributes": attributes, "references": list(references)}


def meta(query, *, with_index=True):
    source = {"query": {"language": "kuery", "query": query}, "filter": []}
    if with_index:
        source["indexRefName"] = "kibanaSavedObjectMeta.searchSourceJSON.index"
    return {"searchSourceJSON": json.dumps(source)}


def index_ref():
    return [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": DATA_VIEW}]


def chart(object_id, title, kind, params, aggs, query, *, with_index=True):
    visual = {"title": title, "type": kind, "params": params, "aggs": aggs}
    return saved(object_id, "visualization",
                 {"title": title, "visState": json.dumps(visual), "description": "",
                  "uiStateJSON": "{}", "kibanaSavedObjectMeta": meta(query, with_index=with_index)},
                 index_ref() if with_index else [])


def text_panel(object_id, title, content):
    return chart(object_id, title, "markdown", {"markdown": content, "fontSize": 15,
                                              "openLinksInNewTab": False}, [], "", with_index=False)


def search(object_id, title, query, columns):
    return saved(object_id, "search",
                 {"title": title, "description": "", "columns": columns,
                  "sort": [["timestamp", "desc"]], "kibanaSavedObjectMeta": meta(query)}, index_ref())


def objects(report, cases):
    data_view = saved(DATA_VIEW, "index-pattern",
                      {"title": "wazuh-alerts-4.x-*", "timeFieldName": "timestamp", "fields": "[]"})
    count = {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}
    status = report["agent"]
    end = report["checked_at"]
    rows = report["scenarios"]
    certified = sum(row["passed"] for row in rows)
    live = sum(row["passed"] and row["source"].startswith("live:") for row in rows)
    pulse = (f'**{status["name"]}** · {status["status"]} · agent {status["id"]}\n\n'
             f'{status["version"]}  \n'
             f'Observed at {end[:19].replace("T", " ")} UTC\n\n'
             "Use the Wazuh Agents view for current status.")
    coverage = (f'**{certified} / {len(rows)} scenarios verified** · run **{report["run"]}**\n\n'
                f'{live} live scenarios · {certified - live} fixture scenarios\n\n'
                "A pass requires an indexed alert and an observed negative control.")
    ready_cases = "\n".join(f'- **{case["id"]}** · {case["title"]} · {case["status"]}' for case in cases)
    incidents = ready_cases or "Investigation summaries are pending."
    group_filter = "rule.groups : soc_lab or rule.id : 5763"
    common_fields = ["rule.id", "rule.description", "rule.level"]
    start = report.get("control_start", "now-1h")
    panels = [
        (text_panel("soc-connected", "Connected endpoints", pulse), 0, 0, 16, 11),
        (chart("soc-volume", "Lab alert volume", "metric",
               {"metric": {"percentageMode": False, "labels": {"show": True},
                           "style": {"fontSize": 50, "bgFill": "#ffffff"}}},
               [count], group_filter), 16, 0, 12, 11),
        (chart("soc-levels", "Alert severity levels", "table",
               {"perPage": 5, "showMetricsAtAllLevels": False, "showPartialRows": False},
               [count, {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
                        "params": {"field": "rule.level", "size": 8, "order": "desc", "orderBy": "1"}}],
               group_filter), 28, 0, 20, 11),
        (search("soc-auth", "Authentication and identity alerts",
                "rule.groups : soc_identity or rule.groups : authentication_failed or rule.id : 5763",
                common_fields), 0, 11, 24, 14),
        (search("soc-fim", "File integrity alerts", "rule.id : 100104",
                ["syscheck.path", *common_fields[:2]]), 24, 11, 24, 14),
        (search("soc-network", "Suricata alerts", "rule.groups : soc_network",
                ["data.alert.signature", "data.dest_port", "data.in_iface", "rule.level"]),
         0, 25, 48, 10),
        (text_panel("soc-coverage", "Detection coverage", coverage), 0, 35, 24, 10),
        (text_panel("soc-cases", "Investigation status", incidents), 24, 35, 24, 10),
    ]
    references = []
    layout = []
    for index, (item, x, y, width, height) in enumerate(panels, start=1):
        ref = f"panel_{index}"
        references.append({"name": ref, "id": item["id"], "type": item["type"]})
        layout.append({"version": VERSION, "type": item["type"], "panelRefName": ref,
                       "panelIndex": str(index), "embeddableConfig": {},
                       "gridData": {"x": x, "y": y, "w": width, "h": height, "i": str(index)}})
    return [data_view, *(entry[0] for entry in panels), saved(DASHBOARD, "dashboard", {
        "title": "Enterprise SOC Operations", "description": f"Lab run {report['run']}",
        "panelsJSON": json.dumps(layout), "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "timeRestore": True, "timeFrom": start, "timeTo": end, "version": 1,
        "kibanaSavedObjectMeta": meta("", with_index=False),
    }, references)]


def export(data):
    return "".join(json.dumps(item, separators=(",", ":")) + "\n" for item in data).encode()


def dashboard_key_pin():
    certificate = health.STATE / "pki/wazuh.dashboard.pem"
    public_key = subprocess.check_output(["openssl", "x509", "-in", certificate, "-pubkey", "-noout"])
    spki = subprocess.check_output(["openssl", "pkey", "-pubin", "-outform", "DER"], input=public_key)
    return base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def login_and_import(page, env, data):
    if not page.url.startswith(BASE + "/"):
        raise RuntimeError("The dashboard login page left the configured loopback origin")
    result = page.evaluate("""async ({username, password, objects}) => {
        const login = await fetch('/auth/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'osd-xsrf': 'true'},
            body: JSON.stringify({username, password}),
            redirect: 'error',
            signal: AbortSignal.timeout(20000)
        });
        if (!login.ok) return {stage: 'login', status: login.status};

        const form = new FormData();
        const blob = new Blob([objects], {type: 'application/ndjson'});
        form.append('file', blob, 'soc-operations.ndjson');
        const upload = await fetch('/api/saved_objects/_import?overwrite=true', {
            method: 'POST',
            headers: {'osd-xsrf': 'true'},
            body: form,
            redirect: 'error',
            signal: AbortSignal.timeout(30000)
        });
        const response = upload.ok ? await upload.json() : {};
        return {stage: 'import', status: upload.status, success: response.success === true};
    }""", {"username": env["INDEXER_USERNAME"], "password": env["INDEXER_PASSWORD"], "objects": data.decode("utf-8")})
    if not result.get("success"):
        raise RuntimeError(f"Dashboard {result['stage']} failed (HTTP {result['status']})")


def capture_agents(page, agent, output):
    page.goto(AGENTS_URL, wait_until="domcontentloaded", timeout=20000)
    ip_heading = re.compile(r"^IP address\b", re.IGNORECASE)
    table = page.get_by_role("table").filter(has=page.get_by_role("columnheader", name=ip_heading))
    name = page.get_by_text(agent["name"], exact=True)
    rows = table.locator("tbody tr")
    row = rows.filter(has=name)
    row.get_by_text(agent["id"], exact=True).wait_for(timeout=60000)
    row.get_by_text(re.compile(r"^active$", re.IGNORECASE)).wait_for(timeout=15000)
    ip_column = table.get_by_role("columnheader", name=ip_heading)
    ip_index = ip_column.evaluate("header => header.cellIndex")
    other_agents = rows.filter(has_not=name)
    table.screenshot(path=output / "soc-agents.png", animations="disabled",
                     mask=[row.locator("td").nth(ip_index), other_agents], mask_color="#28384b")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--cases", type=Path, default=health.ROOT / "docs/incidents/status.json")
    parser.add_argument("--chromium", type=Path, help="reuse an installed Chromium executable")
    parser.add_argument("--headed", action="store_true", help="open Chromium on the host desktop while capturing")
    parser.add_argument("--export-only", action="store_true")
    args = parser.parse_args()
    report = json.loads(args.report.read_text())
    cases = json.loads(args.cases.read_text()) if args.cases.exists() else []
    cases_in_report = [row["scenario"] for row in report["scenarios"]]
    if len(cases_in_report) != 10 or set(cases_in_report) != {f"D{number:02d}" for number in range(1, 11)}:
        parser.error("a completed report with one result for each of the ten scenarios is required")
    os.umask(0o077)
    data = export(objects(report, cases))
    output = Path(tempfile.mkdtemp(prefix="dashboard-", dir=args.report.resolve().parent))
    (output / "soc-operations.ndjson").write_bytes(data)
    if args.export_only:
        print(f"Exported dashboard saved objects to {output}")
        return
    from playwright.sync_api import Error as PlaywrightError, sync_playwright

    health.dashboard_tls()
    pin = dashboard_key_pin()
    env = health.config()
    # Keep debugging and key logging off in this credential-bearing browser session.
    for variable in ("DEBUG", "PWDEBUG", "SSLKEYLOGFILE"):
        os.environ.pop(variable, None)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=args.chromium, chromium_sandbox=True, headless=not args.headed,
            args=["--no-proxy-server", f"--ignore-certificate-errors-spki-list={pin}"],
        )
        context = browser.new_context(viewport={"width": 1470, "height": 1050},
                                      device_scale_factor=1, timezone_id="UTC", service_workers="block")
        context.route("**/*", lambda route: route.continue_() if route.request.url.startswith(BASE + "/")
                      else route.abort())
        page = context.new_page()
        page.goto(BASE + "/app/login", wait_until="domcontentloaded", timeout=20000)
        try:
            login_and_import(page, env, data)
        except PlaywrightError:
            raise RuntimeError("Dashboard login or import request failed") from None
        page.goto(BASE + "/app/dashboards#/view/" + DASHBOARD, wait_until="domcontentloaded")
        page.get_by_text("Enterprise SOC Operations", exact=True).first.wait_for(timeout=45000)
        auth = next(row for row in report["scenarios"] if row["scenario"] == "D01")
        for alert in auth["observed_alerts"]:
            page.get_by_text(alert["rule"]["description"], exact=True).first.wait_for(timeout=15000)
        page.get_by_text("File integrity alerts", exact=True).first.wait_for(timeout=45000)
        page.get_by_text("SOC lab: Monitored inventory file changed", exact=True).first.wait_for(timeout=45000)
        page.screenshot(path=output / "soc-operations.png", full_page=True, animations="disabled")
        network = page.get_by_text("Suricata alerts", exact=True).first
        network.scroll_into_view_if_needed(timeout=15000)
        page.get_by_text("SOC Lab DNS namespace outside inventory allowlist", exact=True).first.wait_for(timeout=30000)
        page.screenshot(path=output / "soc-network.png", animations="disabled")
        capture_agents(context.new_page(), report["agent"], output)
        browser.close()
    print(f"Captured verified dashboard in {output}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        sys.exit(str(exc))
