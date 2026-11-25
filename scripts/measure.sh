#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
PODMAN=${SOC_PODMAN:-/usr/bin/podman}
date -u +'%FT%TZ'
free -m
df -h "$ROOT"
"$PODMAN" stats --no-stream --format 'table {{.Name}}\t{{.CPU}}\t{{.MemUsage}}\t{{.MemPerc}}' \
  enterprise-soc-manager enterprise-soc-indexer enterprise-soc-dashboard
if [[ -s "$ROOT/restricted/linux/qemu.pid" ]] && "$ROOT/scripts/linux_vm.sh" status; then
  ps -p "$(cat "$ROOT/restricted/linux/qemu.pid")" -o rss=,pcpu=,comm=
  du -h "$ROOT/restricted/linux/disk.qcow2" "$ROOT/restricted/downloads/"*.qcow2
fi
