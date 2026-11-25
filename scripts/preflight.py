#!/usr/bin/env python3
"""Read-only capacity and dependency check; does not provision the host."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def probe(command):
    try:
        result = subprocess.run(command, text=True, capture_output=True, timeout=15, check=False)
        return {"ok": result.returncode == 0, "output": (result.stdout or result.stderr).strip()}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "output": str(exc)}


def inspect(path):
    memory = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        if key in ('MemTotal', 'MemAvailable'):
            memory[key] = int(value.split()[0]) * 1024
    disk = shutil.disk_usage(path)
    podman = os.environ.get("SOC_PODMAN", "/usr/bin/podman")
    return {
        'cpu_logical': os.cpu_count(),
        'memory_total_bytes': memory.get('MemTotal'),
        'memory_available_bytes': memory.get('MemAvailable'),
        'filesystem_free_bytes': disk.free,
        'kvm_accessible': os.access('/dev/kvm', os.R_OK | os.W_OK),
        'vm_max_map_count': int(Path('/proc/sys/vm/max_map_count').read_text()),
        'podman': probe([podman, '--version']),
        'podman_runtime': probe([podman, 'info', '--format', '{{.Host.Security.Rootless}}']),
        'qemu': probe(['qemu-system-x86_64', '--version']),
        'commands': {name: bool(shutil.which(name)) for name in
                     ('curl', 'openssl', 'ssh', 'ssh-keygen', 'genisoimage', 'nc', 'qemu-img')},
        'libvirt_system': probe(['virsh', '-c', 'qemu:///system', 'list', '--all']),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--path', default='.', help='filesystem to assess')
    args = parser.parse_args()
    try:
        report = inspect(args.path)
    except (OSError, ValueError) as exc:
        print(f'preflight failed: {exc}', file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
