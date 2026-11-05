#!/usr/bin/env bash
# Purely synthetic Docker network topology regression; no real Codex or keys.
set -euo pipefail

id="apnet$(date +%s)$$"
agent_net="$id""_agent"
db_net="$id""_database"
witness_net="$id""_witness"
gateway="$id""_gateway"
db="$id""_db"
witness="$id""_witness_server"

cleanup() {
  docker rm -f "$gateway" "$witness" "$db" >/dev/null 2>&1 || true
  docker network rm "$agent_net" "$db_net" "$witness_net" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create --internal "$agent_net" >/dev/null
docker network create --internal "$db_net" >/dev/null
docker network create --internal "$witness_net" >/dev/null

# Disposable DB credentials never enter agent container. No published DB port.
docker run -d --name "$db" --network "$db_net" \
  -e POSTGRES_PASSWORD=disposable-local-only \
  -e POSTGRES_DB=postgres \
  postgres:16-alpine >/dev/null

# Unauthenticated synthetic test endpoints. These are NOT production services.
docker run -d --name "$gateway" --network "$agent_net" \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  python:3.12-alpine python -m http.server 8080 --bind 0.0.0.0 >/dev/null
docker network connect "$db_net" "$gateway"
docker network connect "$witness_net" "$gateway"

docker run -d --name "$witness" --network "$witness_net" \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  python:3.12-alpine python -m http.server 9090 --bind 0.0.0.0 >/dev/null

db_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$db")"
witness_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$witness")"
test -n "$db_ip" && test -n "$witness_ip"
echo "Checking gateway access to protected network segments..."
for attempt in $(seq 1 20); do
  if docker exec "$gateway" python -c '
import socket,sys
for host,port in [(sys.argv[1],5432),(sys.argv[2],9090)]:
    with socket.create_connection((host,port),timeout=1): pass
' "$db_ip" "$witness_ip" >/dev/null 2>&1; then
    break
  fi
  if [ "$attempt" -eq 20 ]; then
    echo "Gateway could not reach its protected destinations" >&2
    exit 1
  fi
  sleep 1
done

echo "Probing from unprivileged, read-only, no-capabilities agent namespace..."
docker run --rm -i --network "$agent_net" \
  --user 65534:65534 --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges \
  -e GW_NAME="$gateway" -e DB_IP="$db_ip" -e WITNESS_IP="$witness_ip" \
  python:3.12-alpine python - <<'PY'
import os, socket
def available(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False

assert available(os.environ["GW_NAME"],8080), "agent cannot reach allowed gateway"
# Name-based isolation is insufficient: attempt numeric protected IPs too.
for name,host,port in [
    ("database hostname", "database", 5432),
    ("database private IP", os.environ["DB_IP"], 5432),
    ("witness hostname", "witness", 9090),
    ("witness private IP", os.environ["WITNESS_IP"], 9090),
    ("external IP egress", "1.1.1.1", 443),
]:
    if available(host,port):
        raise AssertionError("agent crossed unauthorized route: " + name)
assert not os.path.exists("/var/run/docker.sock"), "Docker socket exposed"
assert os.getuid() == 65534, "agent is privileged"
print("PASS: agent can reach gateway but not DB, witness, Internet or Docker socket")
PY

echo "PASS: gateway can reach protected DB and witness networks; agent cannot."
