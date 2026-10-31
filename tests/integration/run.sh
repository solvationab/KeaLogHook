#!/usr/bin/env bash
# End-to-end test: a real kea-dhcp4 with this hook, driven by a simulated relay agent
# (relay_client.py) that sends option 82 from a separate network namespace.
#
# Needs root, iproute2, python3 and kea-dhcp4. Run it after installing the hook:
#   sudo cmake --install build
#   sudo tests/integration/run.sh
#
# Environment: KEA_DHCP4 (default /usr/sbin/kea-dhcp4) and HOOK_LIBRARY (default: the installed
# libdhcp_ip_audit.so in Kea's hooks directory). Kea only loads hooks from its own hooks directory.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KEA_DHCP4="${KEA_DHCP4:-/usr/sbin/kea-dhcp4}"
if [ -z "${HOOK_LIBRARY:-}" ]; then
    for candidate in /usr/lib/*/kea/hooks/libdhcp_ip_audit.so /usr/lib64/kea/hooks/libdhcp_ip_audit.so \
                     /usr/lib/kea/hooks/libdhcp_ip_audit.so; do
        if [ -f "$candidate" ]; then HOOK_LIBRARY="$candidate"; break; fi
    done
fi
: "${HOOK_LIBRARY:?hook library not found; install it first (cmake --install build)}"

NS=ip-audit-relay
SERVER_IF=ipa-kea
RELAY_IF=ipa-relay
SERVER_IP=10.99.0.1
RELAY_IP=10.99.0.2
MAC=aa:bb:cc:00:00:01

WORK="$(mktemp -d)"
AUDIT_LOG="$WORK/ip-audit.log"
KEA_LOG="$WORK/kea.log"
KEA_PID=""

cleanup() {
    status=$?
    if [ -n "$KEA_PID" ]; then kill "$KEA_PID" 2>/dev/null || true; wait "$KEA_PID" 2>/dev/null || true; fi
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$SERVER_IF" 2>/dev/null || true
    if [ "$status" -ne 0 ]; then
        echo "--- kea log ---"; cat "$KEA_LOG" 2>/dev/null || true
        echo "--- audit log ---"; cat "$AUDIT_LOG" 2>/dev/null || true
    fi
    rm -rf "$WORK"
    exit "$status"
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then echo "must run as root" >&2; exit 2; fi

# A copy of the binary runs outside the AppArmor profile shipped with the distribution package.
cp "$KEA_DHCP4" "$WORK/kea-dhcp4"

cat > "$WORK/kea-dhcp4.conf" <<EOF
{
  "Dhcp4": {
    "interfaces-config": { "interfaces": ["$SERVER_IF"], "dhcp-socket-type": "udp" },
    "control-socket": { "socket-type": "unix", "socket-name": "$WORK/kea-ctrl.sock" },
    "lease-database": { "type": "memfile", "persist": false },
    "valid-lifetime": 600,
    "subnet4": [
      {
        "id": 1,
        "subnet": "10.99.0.0/24",
        "user-context": { "pop": "test-pop", "site": "test-site" },
        "pools": [ { "pool": "10.99.0.100 - 10.99.0.200" } ]
      }
    ],
    "hooks-libraries": [
      {
        "library": "$HOOK_LIBRARY",
        "parameters": { "queue-size": 100, "sinks": [ { "type": "file", "path": "$AUDIT_LOG" } ] }
      }
    ],
    "loggers": [
      { "name": "kea-dhcp4", "severity": "INFO", "output_options": [ { "output": "$KEA_LOG" } ] }
    ]
  }
}
EOF

export KEA_PIDFILE_DIR="$WORK" KEA_LOCKFILE_DIR="$WORK"

ip netns add "$NS"
ip link add "$SERVER_IF" type veth peer name "$RELAY_IF"
ip link set "$RELAY_IF" netns "$NS"
ip addr add "$SERVER_IP/24" dev "$SERVER_IF"
ip link set "$SERVER_IF" up
ip -n "$NS" addr add "$RELAY_IP/24" dev "$RELAY_IF"
ip -n "$NS" link set "$RELAY_IF" up
ip -n "$NS" link set lo up

echo "Checking the configuration"
"$WORK/kea-dhcp4" -t "$WORK/kea-dhcp4.conf"

echo "Starting kea-dhcp4"
"$WORK/kea-dhcp4" -c "$WORK/kea-dhcp4.conf" &
KEA_PID=$!

for _ in $(seq 1 50); do
    if ! kill -0 "$KEA_PID" 2>/dev/null; then echo "kea-dhcp4 exited early" >&2; exit 1; fi
    if grep -q DHCP4_STARTED "$KEA_LOG" 2>/dev/null; then break; fi
    sleep 0.2
done
grep -q DHCP4_STARTED "$KEA_LOG" || { echo "kea-dhcp4 did not start" >&2; exit 1; }
grep -q IP_AUDIT_LOAD_OK "$KEA_LOG" || { echo "the hook was not loaded" >&2; exit 1; }

echo "Running the relay client"
LEASE="$(ip netns exec "$NS" python3 "$HERE/relay_client.py" --server "$SERVER_IP" --relay "$RELAY_IP" --mac "$MAC")"
echo "$LEASE"
IP="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["ip"])' "$LEASE")"

python3 "$HERE/check_audit_log.py" "$AUDIT_LOG" \
    --ip "$IP" --mac "$MAC" --giaddr "$RELAY_IP" \
  --circuit-id 706f72742d37 --remote-id 0a1b2c3d4e5f \
  --pop test-pop --site test-site

python3 "$HERE/control_client.py" "$WORK/kea-ctrl.sock" "$AUDIT_LOG"

echo "Integration test passed"
