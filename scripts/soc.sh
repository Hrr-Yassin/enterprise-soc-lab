#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
STATE="$ROOT/restricted/wazuh/native"
PODMAN=${SOC_PODMAN:-/usr/bin/podman}
PYTHON=${SOC_PYTHON:-python3}
PREFIX=enterprise-soc
LABEL=io.enterprise-soc-lab.owner
OWNER=enterprise-soc-lab
NETWORK="$PREFIX-mgmt"
INDEXER="$PREFIX-indexer"
MANAGER="$PREFIX-manager"
DASHBOARD="$PREFIX-dashboard"
RULE_SOURCE="$ROOT/detections/rules.xml"
DEPLOYED_RULES="$STATE/manager/etc/rules/enterprise_soc.xml"
VOLUMES=(indexer indexer-logs api etc logs queue multigroups integrations active-response agentless wodles filebeat-etc filebeat-data dashboard-config dashboard-assets)

# Daemons and rootless port forwarders must not inherit the lifecycle lock.
podman() { "$PODMAN" "$@" 9>&-; }

owned() {
  [[ $(podman "$1" inspect --format "{{index .Labels \"$LABEL\"}}" "$2") == "$OWNER" ]]
}
need() { command -v -- "$1" >/dev/null || { echo "Missing command: $1" >&2; exit 1; }; }
fail() { printf '%s\n' "$*" >&2; exit 1; }

# Avoid mutating a same-named object from another project.
container_exists() {
  if podman container exists "$1"; then
    [[ $(podman container inspect --format "{{index .Config.Labels \"$LABEL\"}}" "$1") == "$OWNER" ]] ||
      fail "Container $1 already belongs to a different project"
    return 0
  fi
  return 1
}

volume() {
  local name="$PREFIX-$1"
  if podman volume exists "$name"; then
    owned volume "$name" || fail "Volume $name already belongs to a different project"
  else
    podman volume create --label "$LABEL=$OWNER" "$name" >/dev/null
  fi
}

mounts() {
  local entry
  VOLUME_ARGS=()
  for entry in "$@"; do VOLUME_ARGS+=(-v "$PREFIX-$entry"); done
}

start_service() {
  local name="$1" alias="$2" memory="$3" cpus="$4"
  shift 4
  local nofile=65536
  if [[ $name == "$MANAGER" ]]; then nofile=524288; fi
  if ! container_exists "$name"; then
    podman create --name "$name" --label "$LABEL=$OWNER" --hostname "$alias" \
      --network "$NETWORK:alias=$alias" --memory "$memory" --cpus "$cpus" \
      --ulimit "nofile=$nofile:$nofile" --stop-timeout 45 --http-proxy=false \
      --log-driver k8s-file --log-opt max-size=25mb "$@" >/dev/null
  fi
  if [[ $(podman container inspect --format '{{.State.Running}}' "$name") != true ]]; then
    podman start "$name" >/dev/null
  fi
}

start() {
  local indexer_dir=/usr/share/wazuh-indexer
  local dashboard_dir=/usr/share/wazuh-dashboard
  local pki="$STATE/pki"
  local lock="$ROOT/config/central-images.env"
  [[ -r "$pki/ca.pem" ]] || fail "Run soc.sh init and soc.sh certs first"
  local maps
  read -r maps < /proc/sys/vm/max_map_count
  (( maps >= 262144 )) || fail "The indexer requires vm.max_map_count >= 262144"
  # shellcheck source=/dev/null
  source "$lock"
  if podman network exists "$NETWORK"; then
    [[ $(podman network inspect --format "{{index .Labels \"$LABEL\"}} {{.Internal}}" "$NETWORK") == "$OWNER true" ]] ||
      fail "Network $NETWORK has unexpected ownership or isolation"
  else
    podman network create --internal --label "$LABEL=$OWNER" "$NETWORK" >/dev/null
  fi
  local item
  for item in "${VOLUMES[@]}"; do volume "$item"; done
  [[ -e "$DEPLOYED_RULES" ]] || install -m 0644 "$RULE_SOURCE" "$DEPLOYED_RULES"
  mounts api:/var/ossec/api/configuration etc:/var/ossec/etc logs:/var/ossec/logs \
    queue:/var/ossec/queue multigroups:/var/ossec/var/multigroups integrations:/var/ossec/integrations \
    active-response:/var/ossec/active-response/bin agentless:/var/ossec/agentless \
    wodles:/var/ossec/wodles filebeat-etc:/etc/filebeat filebeat-data:/var/lib/filebeat
  start_service "$MANAGER" wazuh.manager 1536m 2 \
    "${VOLUME_ARGS[@]}" --env-file "$STATE/manager.env" -p 127.0.0.1:15140:1514/tcp \
    -v "$pki/ca.pem:/etc/ssl/soc-ca.pem:ro,z" \
    -v "$pki/wazuh.manager.pem:/etc/ssl/soc-filebeat.pem:ro,z" \
    -v "$pki/wazuh.manager.key:/etc/ssl/soc-filebeat.key:ro,z" \
    -v "$STATE/manager:/wazuh-config-mount:ro,z" \
    -v "$ROOT/config/manager-entrypoint.sh:/entrypoint-scripts/100-enterprise-soc.sh:ro,z" "$SOC_MANAGER_IMAGE"
  [[ ${1:-} == manager ]] && return 0
  mounts "indexer:/var/lib/wazuh-indexer" "indexer-logs:/var/log/wazuh-indexer"
  start_service "$INDEXER" wazuh.indexer 3072m 2 \
    "${VOLUME_ARGS[@]}" -e 'OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g' \
    -v "$pki/ca.pem:$indexer_dir/config/certs/root-ca.pem:ro,z" \
    -v "$pki/wazuh.indexer.pem:$indexer_dir/config/certs/wazuh.indexer.pem:ro,z" \
    -v "$pki/wazuh.indexer.key:$indexer_dir/config/certs/wazuh.indexer.key:ro,z" \
    -v "$STATE/indexer.yml:$indexer_dir/config/opensearch.yml:ro,z" \
    -v "$STATE/internal_users.yml:$indexer_dir/config/opensearch-security/internal_users.yml:ro,z" \
    "$SOC_INDEXER_IMAGE"
  [[ ${1:-} == backends ]] && return 0
  mounts "dashboard-config:$dashboard_dir/data/wazuh/config" "dashboard-assets:$dashboard_dir/plugins/wazuh/public/assets/custom"
  start_service "$DASHBOARD" wazuh.dashboard 1536m 1.5 \
    "${VOLUME_ARGS[@]}" --env-file "$STATE/dashboard.env" -p 127.0.0.1:8443:5601/tcp \
    -v "$pki/ca.pem:$dashboard_dir/certs/root-ca.pem:ro,z" \
    -v "$pki/wazuh.dashboard.pem:$dashboard_dir/certs/wazuh-dashboard.pem:ro,z" \
    -v "$pki/wazuh.dashboard.key:$dashboard_dir/certs/wazuh-dashboard-key.pem:ro,z" \
    -v "$STATE/dashboard.yml:$dashboard_dir/config/opensearch_dashboards.yml:ro,z" \
    -v "$ROOT/config/verify-manager-tls.cjs:/etc/enterprise-soc/verify-manager-tls.cjs:ro,z" \
    -v "$STATE/dashboard-wazuh.yml:$dashboard_dir/data/wazuh/config/wazuh.yml:ro,z" \
    "$SOC_DASHBOARD_IMAGE"
  printf '%s\n' "Central containers started. Run soc.sh health --wait 180 for readiness."
}

stop() {
  local name
  for name in "$DASHBOARD" "$MANAGER" "$INDEXER"; do
    if container_exists "$name"; then podman stop --ignore "$name" >/dev/null; fi
  done
}

cleanup() {
  local name
  stop
  for name in "$DASHBOARD" "$MANAGER" "$INDEXER"; do
    if container_exists "$name"; then podman rm "$name" >/dev/null; fi
  done
  if podman network exists "$NETWORK"; then
    owned network "$NETWORK" || fail "Refusing to remove unowned network $NETWORK"
    podman network rm "$NETWORK" >/dev/null
  fi
  if [[ ${1:-} == --purge-data ]]; then
    for name in "${VOLUMES[@]}"; do
      local volume_name="$PREFIX-$name"
      if podman volume exists "$volume_name"; then
        owned volume "$volume_name" || fail "Refusing to remove unowned volume $volume_name"
        podman volume rm "$volume_name" >/dev/null
      fi
    done
  fi
}

reload_rules() (
  container_exists "$MANAGER" || fail "Start the manager first"
  local staging
  staging=$(mktemp -d -- "${DEPLOYED_RULES%/*}/.reload.XXXXXX")
  trap 'rm -rf -- "$staging"' EXIT
  install -m 0644 "$RULE_SOURCE" "$staging/candidate"
  cp -p -- "$DEPLOYED_RULES" "$staging/prior"

  podman exec -i "$MANAGER" sh -ec '
    rules=/var/ossec/etc/rules/enterprise_soc.xml
    staging=$(mktemp -d)
    cp -p "$rules" "$staging/original"
    restore() {
      cp -p "$staging/original" "$rules"
      rm -rf "$staging"
    }
    trap restore EXIT
    trap "exit 1" HUP INT TERM
    cat > "$staging/candidate"
    install -o root -g wazuh -m 0640 "$staging/candidate" "$rules"
    /var/ossec/bin/wazuh-analysisd -t
  ' < "$staging/candidate"

  # Publish exactly the validated bytes. Keep the previous rules until Podman accepts the restart.
  mv -f -- "$staging/candidate" "$DEPLOYED_RULES"
  if podman restart "$MANAGER"; then
    exit 0
  fi
  if ! mv -f -- "$staging/prior" "$DEPLOYED_RULES"; then
    trap - EXIT
    fail "Manager restart and rule rollback failed. Previous rules are in $staging/prior"
  fi
  if podman restart "$MANAGER" >/dev/null; then
    fail "Manager restart failed with the candidate rules. Previous rules restored. Check SOC health."
  fi
  fail "Previous rules restored, but the manager recovery restart failed. Check SOC health."
)

case "${1:-}" in
  init|certs) exec "$PYTHON" -B "$ROOT/scripts/init_stack.py" "$1" ;;
  health) shift; exec "$PYTHON" -B "$ROOT/scripts/health.py" "$@" ;;
  start|stop|cleanup|reload-rules)
    need "$PODMAN"
    if [[ $(podman info --format '{{.Host.Security.Rootless}}') != true ]]; then
      fail "Run this lab under a rootless Podman account"
    fi
    [[ -d "$STATE" ]] || fail "Run soc.sh init first"
    exec 9>"$STATE/lifecycle.lock"
    flock 9
    case "$1" in
      start)
        (( $# == 1 )) || [[ $# == 2 && ( $2 == manager || $2 == backends ) ]] || fail "Use start [manager|backends]"
        start "${2:-}" ;;
      stop) stop ;;
      cleanup)
        (( $# == 1 )) || [[ $# == 2 && $2 == --purge-data ]] || fail "Use cleanup [--purge-data]"
        cleanup "${2:-}" ;;
      reload-rules) reload_rules ;;
    esac ;;
  *) printf 'Usage: %s {init|certs|start|health|stop|cleanup|reload-rules}\n' "$0" >&2; exit 2 ;;
esac
