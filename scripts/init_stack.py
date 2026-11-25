#!/usr/bin/env python3
"""Initialize an isolated Wazuh configuration and generate its local PKI."""

import argparse
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "vendor/wazuh/single-node/config"
RUNTIME = ROOT / "restricted/wazuh"
DN = "/C=US/L=California/O=Wazuh/OU=Wazuh"


def password():
    return "Aa1!" + secrets.token_hex(20)


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("Expected exactly one occurrence of a pinned upstream setting")
    return text.replace(old, new, 1)


def manager_config(source):
    config = source.read_text()
    config = replace_once(config, "<logall_json>no", "<logall_json>yes")
    config = replace_once(config, "<vulnerability-detection>\n    <enabled>yes", "<vulnerability-detection>\n    <enabled>no")
    config = replace_once(config, "<auth>\n    <disabled>no", "<auth>\n    <disabled>no</disabled>\n    <remote_enrollment>no")
    config = replace_once(config, "<agents_disconnection_time>10m", "<agents_disconnection_time>2m")
    config = replace_once(config, "<agents_disconnection_alert_time>0", "<agents_disconnection_alert_time>30s")
    return config


def write(path, value, mode=0o600):
    path.write_text(value, encoding="utf-8")
    path.chmod(mode)


def write_env(path, values):
    write(path, "".join(f"{key}={value}\n" for key, value in values.items()))


def initialize():
    import bcrypt

    target = RUNTIME / "native"
    if target.exists():
        raise FileExistsError(f"{target} already exists. Use the existing private configuration.")
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    if RUNTIME.is_symlink() or RUNTIME.stat().st_mode & 0o077:
        raise ValueError("The Wazuh runtime must be a private directory (0700)")
    with tempfile.TemporaryDirectory(dir=RUNTIME) as pending:
        staging = Path(pending) / "native"
        staging.mkdir(mode=0o700)
        manager = staging / "manager"
        (manager / "etc/rules").mkdir(parents=True)
        (manager / "api/configuration/ssl").mkdir(parents=True)
        write(manager / "etc/ossec.conf", manager_config(SOURCE / "wazuh_cluster/wazuh_manager.conf"))
        admin, dashboard, api = password(), password(), password()
        write(staging / "credentials.txt", f"Dashboard username: admin\nDashboard password: {admin}\n")
        write_env(staging / "manager.env", {
            "INDEXER_URL": "https://wazuh.indexer:9200",
            "INDEXER_USERNAME": "admin",
            "INDEXER_PASSWORD": admin,
            "FILEBEAT_SSL_VERIFICATION_MODE": "full",
            "SSL_CERTIFICATE_AUTHORITIES": "/etc/ssl/soc-ca.pem",
            "SSL_CERTIFICATE": "/etc/ssl/soc-filebeat.pem",
            "SSL_KEY": "/etc/ssl/soc-filebeat.key",
            "API_USERNAME": "wazuh-wui",
            "API_PASSWORD": api,
        })
        write_env(staging / "dashboard.env", {
            "DASHBOARD_USERNAME": "kibanaserver",
            "DASHBOARD_PASSWORD": dashboard,
            "NODE_OPTIONS": "--require=/etc/enterprise-soc/verify-manager-tls.cjs",
        })
        users = ["---", "_meta:", "  type: internalusers", "  config_version: 2"]
        for username, secret in (("admin", admin), ("kibanaserver", dashboard)):
            hashed = bcrypt.hashpw(secret.encode(), bcrypt.gensalt()).decode()
            users.extend((f"{username}:", f'  hash: "{hashed}"', "  reserved: true"))
            if username == "admin":
                users.append('  backend_roles: ["admin"]')
        write(staging / "internal_users.yml", "\n".join(users) + "\n", 0o444)
        indexer = (SOURCE / "wazuh_indexer/wazuh.indexer.yml").read_text()
        indexer = replace_once(indexer, "cluster.routing.allocation.disk.threshold_enabled: false",
                               "cluster.routing.allocation.disk.threshold_enabled: true")
        write(staging / "indexer.yml", indexer + "\n", 0o444)
        dashboard_config = (SOURCE / "wazuh_dashboard/opensearch_dashboards.yml").read_text()
        dashboard_config = replace_once(dashboard_config, "verificationMode: certificate", "verificationMode: full")
        write(staging / "dashboard.yml", dashboard_config, 0o444)
        write(staging / "dashboard-wazuh.yml",
              f'hosts:\n  - 1513629884013:\n      url: "https://wazuh.manager"\n'
              f'      port: 55000\n      username: wazuh-wui\n      password: "{api}"\n      run_as: true\n',
              0o444)
        staging.rename(target)
    print(f"Initialized private runtime {target}")


def openssl(*args):
    subprocess.run(["openssl", *map(str, args)], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE)


def certificates():
    target = RUNTIME / "native"
    pki = target / "pki"
    if pki.exists():
        raise FileExistsError(f"{pki} already exists")
    with tempfile.TemporaryDirectory(dir=target) as pending:
        staging = Path(pending)
        ca = staging / "ca.pem"
        ca_key = staging / "ca.key"
        openssl("req", "-x509", "-newkey", "rsa:3072", "-noenc", "-sha256", "-days", "730",
                "-subj", "/CN=Enterprise SOC Lab CA",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", ca_key, "-out", ca)
        names = {
            "wazuh.indexer": "DNS:wazuh.indexer",
            "wazuh.manager": "DNS:wazuh.manager",
            "wazuh.dashboard": "DNS:wazuh.dashboard,IP:127.0.0.1",
            "admin": "DNS:admin",
        }
        for name, san in names.items():
            key = staging / f"{name}.key"
            csr = staging / "leaf.csr"
            cert = staging / f"{name}.pem"
            extensions = staging / "extensions"
            extensions.write_text(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
                f"extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName={san}\n"
            )
            openssl("req", "-new", "-newkey", "rsa:2048", "-noenc", "-subj", f"{DN}/CN={name}",
                    "-keyout", key, "-out", csr)
            openssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key, "-CAcreateserial",
                    "-days", "365", "-sha256", "-extfile", extensions, "-out", cert)
            openssl("verify", "-x509_strict", "-CAfile", ca, cert)
        ready = staging / "pki"
        ready.mkdir(mode=0o700)
        for cert in (*staging.glob("*.pem"), *staging.glob("*.key")):
            cert.chmod(0o600 if cert == ca_key else 0o444)
            cert.rename(ready / cert.name)
        api_ssl = target / "manager/api/configuration/ssl"
        for destination, source, mode in (
            ("server.crt", "wazuh.manager.pem", 0o444), ("server.key", "wazuh.manager.key", 0o440),
        ):
            temporary = staging / destination
            shutil.copyfile(ready / source, temporary)
            temporary.chmod(mode)
            temporary.replace(api_ssl / destination)
        ready.rename(pki)
    print("Created and verified the project CA and service certificates")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init", "certs"), nargs="?", default="init")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        {"init": initialize, "certs": certificates}[args.command]()
    except ImportError as exc:
        sys.exit(f"Install the pinned requirements first: {exc}")
    except subprocess.CalledProcessError as exc:
        sys.exit(exc.stderr.decode().strip())
    except (OSError, ValueError) as exc:
        sys.exit(str(exc))


if __name__ == "__main__":
    main()
