#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
STATE="$ROOT/restricted/linux"
DOWNLOADS="$ROOT/restricted/downloads"
BUILD=20261117-2665
BASE="$DOWNLOADS/debian-12-$BUILD-amd64.qcow2"
SHA512=946b917a37882f16e5b3b0b2cbe5744637d0cd36190b5b53cbb21d14a54557d5b45e9e523021b8f52c1707dbe470489f3515458e0680ded76ee2574b4a8daf1b
URL="https://cloud.debian.org/images/cloud/bookworm/$BUILD/debian-12-genericcloud-amd64-$BUILD.qcow2"
PORT=22223
NAME=soc-linux
SSH="soc@127.0.0.1"
OPTIONS=(-o BatchMode=yes -o ConnectTimeout=4 -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes
         -o UserKnownHostsFile="$STATE/known_hosts" -o GlobalKnownHostsFile=/dev/null -i "$STATE/ssh-client")

fail() { printf '%s\n' "$*" >&2; exit 1; }
verify() { printf '%s  %s\n' "$SHA512" "$1" | sha512sum -c --status; }
ssh_vm() { ssh "${OPTIONS[@]}" -p "$PORT" "$SSH" "$@"; }
live() {
  local stored_pid
  [[ -s "$STATE/qemu.pid" ]] || return 1
  read -r stored_pid < "$STATE/qemu.pid"
  [[ $stored_pid =~ ^[0-9]+$ ]] && kill -0 "$stored_pid" 2>/dev/null || return 1
  tr '\0' '\n' < "/proc/$stored_pid/cmdline" | awk -v image="file=$STATE/disk.qcow2,format=qcow2,if=virtio" \
    -v name="$NAME" '$0 == image { image_ok=1 } $0 == name { name_ok=1 } END { exit !(image_ok && name_ok) }'
}

download() {
  mkdir -p "$DOWNLOADS"
  if [[ -f "$BASE" ]]; then verify "$BASE" || fail "Cached image failed checksum verification"; return; fi
  curl --fail --location --silent --show-error --connect-timeout 20 --max-time 600 \
    --output "$BASE.part" "$URL"
  verify "$BASE.part" || fail "Debian image checksum mismatch"
  mv -- "$BASE.part" "$BASE"
}

prepare() {
  [[ -f "$BASE" ]] && verify "$BASE" || fail "Run linux_vm.sh download first"
  if [[ ! -f "$STATE/seed.iso" ]]; then
    [[ ! -f "$STATE/disk.qcow2" ]] || fail "The existing project disk is missing its cloud-init seed"
    [[ -f "$STATE/ssh-client" ]] || ssh-keygen -q -t ed25519 -N '' -C "$NAME-client" -f "$STATE/ssh-client"
    [[ -f "$STATE/ssh-host" ]] || ssh-keygen -q -t ed25519 -N '' -C "$NAME-host" -f "$STATE/ssh-host"
    printf '[127.0.0.1]:%s %s\n' "$PORT" "$(cut -d ' ' -f1,2 "$STATE/ssh-host.pub")" > "$STATE/known_hosts"
    {
      printf '#cloud-config\nhostname: %s\nmanage_etc_hosts: true\nssh_pwauth: false\ndisable_root: true\n' "$NAME"
      printf 'ssh_deletekeys: true\nssh_keys:\n  ed25519_private: |\n'
      sed 's/^/    /' "$STATE/ssh-host"
      printf '  ed25519_public: %s\n' "$(cat "$STATE/ssh-host.pub")"
      printf 'users:\n  - name: soc\n    lock_passwd: true\n    shell: /bin/bash\n'
      printf '    sudo: ["ALL=(ALL) NOPASSWD:ALL"]\n    ssh_authorized_keys:\n      - %s\n' "$(cat "$STATE/ssh-client.pub")"
    } > "$STATE/user-data"
    printf 'instance-id: enterprise-soc-linux-%s\nlocal-hostname: %s\n' "$BUILD" "$NAME" > "$STATE/meta-data"
    ( cd -- "$STATE" && genisoimage -quiet -o seed.iso.new -V cidata -J -r user-data meta-data )
    mv -- "$STATE/seed.iso.new" "$STATE/seed.iso"
  fi
  if [[ ! -f "$STATE/disk.qcow2" ]]; then
    qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" "$STATE/disk.qcow2.new" 12G
    mv -- "$STATE/disk.qcow2.new" "$STATE/disk.qcow2"
  fi
}

start() {
  if live; then printf '%s is already running. Stop it before changing network mode.\n' "$NAME"; return; fi
  [[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || fail "KVM access is required for the dedicated guest"
  [[ -f "$STATE/disk.qcow2" && -f "$STATE/seed.iso" ]] || fail "Run linux_vm.sh prepare first"
  local mode=isolated
  local net="user,id=socnet,ipv6=off,restrict=on,hostfwd=tcp:127.0.0.1:$PORT-:22"
  if [[ ${1:-} == --bootstrap ]]; then
    mode=bootstrap
    local socket
    socket=$(python3 -c 'import shlex,sys; print(shlex.quote(sys.argv[1]))' "$STATE/update.sock")
    net+=",guestfwd=tcp:10.0.2.101:3142-cmd:/usr/bin/nc -U $socket"
  else
    net+=",guestfwd=tcp:10.0.2.100:1514-cmd:/usr/bin/nc 127.0.0.1 15140"
  fi
  qemu-system-x86_64 -name "$NAME" -machine q35,accel=kvm -cpu host -smp 2 -m 1536 \
    -nodefaults -display none -monitor none -qmp "unix:$STATE/monitor.sock,server=on,wait=off" -serial "file:$STATE/serial.log" \
    -drive "file=$STATE/disk.qcow2,format=qcow2,if=virtio" \
    -drive "file=$STATE/seed.iso,format=raw,if=virtio,readonly=on" \
    -netdev "$net" -device virtio-net-pci,netdev=socnet \
    -pidfile "$STATE/qemu.pid" -daemonize 9>&-
  printf '%s\n' "$mode" > "$STATE/restrict-mode"
}

stop() {
  if ! live; then return; fi
  if ! ssh_vm sudo systemctl poweroff; then
    python3 - "$STATE/monitor.sock" <<'PYQMP'
import json
import socket
import sys

with socket.socket(socket.AF_UNIX) as connection:
    connection.settimeout(5)
    connection.connect(sys.argv[1])
    with connection.makefile("rwb") as channel:
        greeting = json.loads(channel.readline())
        if "QMP" not in greeting:
            raise RuntimeError("Invalid QEMU monitor greeting")
        for command in ("qmp_capabilities", "system_powerdown"):
            channel.write(json.dumps({"execute": command}).encode() + b"\n")
            channel.flush()
            while True:
                response = json.loads(channel.readline())
                if "error" in response:
                    raise RuntimeError(f"QEMU did not accept {command}")
                if "return" in response:
                    break
PYQMP
  fi
  local attempt
  for attempt in {1..30}; do if ! live; then return; fi; sleep 1; done
  fail "The dedicated VM did not exit after a graceful shutdown"
}

stop_proxy() {
  kill "$proxy_pid" 2>/dev/null || true
  wait "$proxy_pid" 2>/dev/null || true
  rm -f -- "$STATE/update.sock"
}

provision() {
  live && [[ $(cat "$STATE/restrict-mode") == bootstrap ]] || fail "Start the guest with --bootstrap"
  ssh_vm cloud-init status --wait
  local socket="$STATE/update.sock"
  [[ ! -L "$socket" && ( ! -e "$socket" || -S "$socket" ) ]] || fail "Unexpected package-proxy path"
  rm -f -- "$socket"
  python3 -B "$ROOT/scripts/update_proxy.py" "$socket" 9>&- &
  proxy_pid=$!
  trap 'stop_proxy' EXIT
  local attempt
  for attempt in {1..50}; do [[ -S $socket ]] && break; sleep 0.1; done
  [[ -S "$socket" ]] || fail "Could not start the package proxy"
  scp -q -P "$PORT" "${OPTIONS[@]}" "$ROOT/endpoints/linux/"{agent.xml,sensor.rules,tune_suricata.py,policy-audit.rules,provision.sh} "$SSH:/home/soc/"
  ssh_vm 'sudo timeout 600 bash /home/soc/provision.sh'
}

mkdir -p "$STATE"
case "${1:-}" in
  download|prepare|start|stop|provision|cleanup)
    exec 9>"$STATE/lifecycle.lock"
    flock 9
    case "$1" in
      download) download ;;
      prepare) prepare ;;
      provision) provision ;;
      start)
        (( $# == 1 )) || [[ $# == 2 && $2 == --bootstrap ]] || fail "Use start [--bootstrap]"
        start "${2:-}" ;;
      stop) stop ;;
      cleanup)
        [[ $# == 2 && $2 == --purge-disk ]] || fail "Use cleanup --purge-disk to remove the dedicated guest state"
        if live; then fail "Stop the dedicated guest before removing its disk"; fi
        rm -f -- "$STATE/"{disk.qcow2,seed.iso,serial.log,ssh-client,ssh-client.pub,ssh-host,ssh-host.pub,known_hosts,user-data,meta-data,qemu.pid,monitor.sock,restrict-mode}
        ;;
    esac ;;
  ssh) shift; ssh_vm "$@" ;;
  put) shift; scp -q -P "$PORT" "${OPTIONS[@]}" "$@" "$SSH:/home/soc/" ;;
  status)
    live || fail "$NAME is stopped"
    mode=$(cat "$STATE/restrict-mode")
    [[ $mode == isolated || $mode == bootstrap ]] || fail "The VM has an older launch configuration"
    printf '%s is running with QEMU restrict=on (%s)\n' "$NAME" "$mode" ;;
  *) fail "Usage: $0 {download|prepare|start [--bootstrap]|provision|stop|cleanup --purge-disk|status|ssh [cmd]|put [files]}" ;;
esac
