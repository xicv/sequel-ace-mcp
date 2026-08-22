#!/usr/bin/env bash
# SSH direct-transport live tests: a bastion (linuxserver/openssh-server)
# with its port published on loopback, and a MariaDB container reachable
# ONLY through the bastion on a private docker network (no published
# MySQL port). Proves the tunnel actually carries the MySQL traffic.
#
# Per-run synthetic credentials (0600 env-file + 0600 key files under the
# isolated test root); the bastion's fresh host key is exported into a
# per-run known_hosts file so strict verification is exercised against
# the REAL key, plus a decoy key file for mismatch testing. Full cleanup
# via trap. Nothing here can reach or read any real configuration.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/isolated-test-env.sh
source scripts/lib/isolated-test-env.sh

WHAT="${1:-mariadb}"
STAMP="$(date +%s)-$$"
NETWORK="sqm-ssh-net-$STAMP"
SSHD_CONTAINER="sqm-sshd-$STAMP"
DB_CONTAINER="sqm-ssh-db-$STAMP"

SECRET_FILE="$(mktemp)"
chmod 600 "$SECRET_FILE"
DB_PASSWORD="$(head -c 18 /dev/urandom | base64 | tr -d '=+/' | head -c 20)"
SSH_USER="tunnel"
SSH_PASSWORD="$(head -c 18 /dev/urandom | base64 | tr -d '=+/' | head -c 20)"

iso_init >/dev/null

cleanup() {
  local rc=$?
  docker rm -f "$SSHD_CONTAINER" "$DB_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  rm -f "$SECRET_FILE"
  rm -rf "${ISO_ROOT:-}"
  exit "$rc"
}
trap cleanup EXIT INT TERM

pick_port() {
  python3 - <<'EOF'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
EOF
}

SSH_PORT="$(pick_port)"

# Client keypair (generated per run; private half lives only under the
# isolated root with 0600).
KEY_DIR="$ISO_ROOT/keys"
mkdir -p "$KEY_DIR" && chmod 700 "$KEY_DIR"
ssh-keygen -q -t ed25519 -N "" -f "$KEY_DIR/id_ed25519" -C "sqm-ssh-test"
# Decoy keypair: its public half masquerades as the "known" host key in
# the mismatch fixture.
ssh-keygen -q -t ed25519 -N "" -f "$KEY_DIR/decoy" -C "sqm-decoy"
PUB_KEY="$(cat "$KEY_DIR/id_ed25519.pub")"

# --- Topology -----------------------------------------------------------
# Private network; MariaDB attached WITHOUT any published port (alias
# "db"); bastion attached to the same network with its SSH port
# published on loopback only. The bastion is a purpose-built alpine
# sshd image (deterministic config: TCP forwarding explicitly enabled,
# password + pubkey auth) so the transport under test is not at the
# mercy of a vendor image's defaults.
docker network create "$NETWORK" >/dev/null

{
  printf 'MARIADB_ROOT_PASSWORD=%s\n' "$DB_PASSWORD"
  printf 'MARIADB_DATABASE=app\n'
} >"$SECRET_FILE"
docker run -d --name "$DB_CONTAINER" --network "$NETWORK" \
  --network-alias db --env-file "$SECRET_FILE" mariadb:11 >/dev/null
rm -f "$SECRET_FILE"

SSHD_BUILD="$(mktemp -d)"
cat >"$SSHD_BUILD/Dockerfile" <<'DOCKER'
# Immutable digest pin (alpine 3.20, resolved 2026-08-22) so the bastion
# base image is byte-stable across runs; the running sshd version is
# printed below.
FROM alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache openssh-server openssh-client
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
DOCKER
cat >"$SSHD_BUILD/entrypoint.sh" <<'ENTRY'
#!/bin/sh
set -eu
ssh-keygen -A
mkdir -p /run/sshd
# Idempotent across container restarts (docker start re-runs this).
adduser -D -s /bin/sh "$USER_NAME" 2>/dev/null || true
echo "$USER_NAME:$USER_PASSWORD" | chpasswd
mkdir -p "/home/$USER_NAME/.ssh"
printf '%s\n' "$PUBLIC_KEY" > "/home/$USER_NAME/.ssh/authorized_keys"
chown -R "$USER_NAME" "/home/$USER_NAME/.ssh"
chmod 700 "/home/$USER_NAME/.ssh"
chmod 600 "/home/$USER_NAME/.ssh/authorized_keys"
cat >/etc/ssh/sshd_config <<'SSHD'
Port 2222
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
# Direct-tcpip (local forwarding from the client's view) is the ONLY
# forwarding this bastion exists for; everything else is off.
AllowTcpForwarding local
PermitOpen any
GatewayPorts no
X11Forwarding no
AllowAgentForwarding no
PermitTunnel no
PermitUserEnvironment no
PermitTTY no
PasswordAuthentication yes
PubkeyAuthentication yes
KbdInteractiveAuthentication no
PermitRootLogin no
UsePAM no
Subsystem sftp internal-sftp
PidFile /run/sshd.pid
SSHD
exec /usr/sbin/sshd -D -e
ENTRY
docker build -q -t "sqm-sshd:$STAMP" "$SSHD_BUILD" >/dev/null
rm -rf "$SSHD_BUILD"

docker run -d --name "$SSHD_CONTAINER" --network "$NETWORK" \
  -p "127.0.0.1:$SSH_PORT:2222" \
  -e USER_NAME="$SSH_USER" -e USER_PASSWORD="$SSH_PASSWORD" \
  -e PUBLIC_KEY="$PUB_KEY" \
  "sqm-sshd:$STAMP" >/dev/null

wait_listening() {
  local port="$1" tries=120 consecutive=0
  for _ in $(seq 1 $tries); do
    if python3 - "$port" <<'EOF'
import socket, sys
s = socket.socket()
s.settimeout(1.0)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
    sys.exit(0)
except OSError:
    sys.exit(1)
finally:
    s.close()
EOF
    then
      consecutive=$((consecutive + 1))
      if [ "$consecutive" -ge 5 ]; then return 0; fi
    else
      consecutive=0
    fi
    sleep 1
  done
  echo "bastion failed to listen on 127.0.0.1:$port" >&2
  return 1
}

wait_healthy_db() {
  local tries=120 consecutive=0
  for _ in $(seq 1 $tries); do
    if docker exec "$DB_CONTAINER" mariadb-admin -uroot -p"$DB_PASSWORD" status >/dev/null 2>&1; then
      consecutive=$((consecutive + 1))
      if [ "$consecutive" -ge 5 ]; then return 0; fi
    else
      consecutive=0
    fi
    sleep 1
  done
  echo "database failed to become healthy" >&2
  return 1
}

wait_listening "$SSH_PORT"
wait_healthy_db

# Bastion-side reachability of the private-network database.
docker exec "$SSHD_CONTAINER" sh -c \
  'nc -z -w 3 db 3306 >/dev/null 2>&1 && echo "==> bastion can reach db:3306" || echo "==> WARNING: bastion cannot reach db:3306"'

# Fetch the bastion's REAL fresh host key (linuxserver keeps host keys
# under /etc/ssh/host_keys; fall back to the standard path).
HOST_PUB="$(docker exec "$SSHD_CONTAINER" cat /etc/ssh/ssh_host_ed25519_key.pub \
  | awk '{print $1" "$2}')"
DECOY_PUB="$(awk '{print $1" "$2}' "$KEY_DIR/decoy.pub")"
if [ -z "$HOST_PUB" ] || [ -z "$DECOY_PUB" ]; then
  echo "failed to export host keys" >&2
  exit 1
fi

# Strict fixtures: the real key (accept), the decoy key (mismatch), and
# an unknown-host file (no matching entry).
GOOD_KNOWN="$ISO_ROOT/known_hosts_good"
BAD_KNOWN="$ISO_ROOT/known_hosts_mismatch"
UNKNOWN_KNOWN="$ISO_ROOT/known_hosts_other"
printf '[127.0.0.1]:%s %s\n' "$SSH_PORT" "$HOST_PUB" >"$GOOD_KNOWN"
printf '[127.0.0.1]:%s %s\n' "$SSH_PORT" "$DECOY_PUB" >"$BAD_KNOWN"
printf '[10.255.255.1]:22 %s\n' "$DECOY_PUB" >"$UNKNOWN_KNOWN"
REVOKED_KNOWN="$ISO_ROOT/known_hosts_revoked"
MALFORMED_KNOWN="$ISO_ROOT/known_hosts_malformed"
MISSING_KNOWN="$ISO_ROOT/known_hosts_does_not_exist"
# The REAL key, but marked revoked.
printf '@revoked [127.0.0.1]:%s %s\n' "$SSH_PORT" "$HOST_PUB" >"$REVOKED_KNOWN"
# Non-empty, structurally unparseable (no line has a key field).
printf 'two-parts-only\n???\nno-key-here\n' >"$MALFORMED_KNOWN"

echo "==> bastion on 127.0.0.1:$SSH_PORT (user $SSH_USER), db reachable only via bastion as db:3306"

# Environment evidence (reviewer requirements): base image digest,
# running sshd version, effective forwarding/auth config, network name,
# proof the database has NO published ports, and the isolated root.
echo "==> bastion base image: alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
echo "==> bastion openssh: $(docker exec "$SSHD_CONTAINER" ssh -V 2>&1 | head -1)"
echo "==> effective sshd config:"
docker exec "$SSHD_CONTAINER" sh -c \
  '/usr/sbin/sshd -T 2>&1 || cat /etc/ssh/sshd_config' | \
  grep -Ei '^(allowtcpforwarding|gatewayports|x11forwarding|allowagentforwarding|permittunnel|permituserenvironment|permittty|passwordauthentication|pubkeyauthentication) ' | sed 's/^/    /'
echo "==> network: $NETWORK (db alias db)"
DB_PORTS="$(docker port "$DB_CONTAINER" | wc -l | tr -d ' ')"
if [ "$DB_PORTS" != "0" ]; then
  echo "FATAL: database container has published ports" >&2
  docker port "$DB_CONTAINER" >&2
  exit 1
fi
echo "==> db published ports: none (verified)"
echo "==> ISO_ROOT=$ISO_ROOT"

iso_export_for_cargo
export SEQUEL_MCP_TEST_ALLOWED_ENDPOINTS="192.0.2.1"
export SEQUEL_MCP_TEST_SSH_BASTION="127.0.0.1:$SSH_PORT:$SSH_USER:$SSH_PASSWORD"
export SEQUEL_MCP_TEST_SSH_KNOWN_GOOD="$GOOD_KNOWN"
export SEQUEL_MCP_TEST_SSH_KNOWN_MISMATCH="$BAD_KNOWN"
export SEQUEL_MCP_TEST_SSH_KNOWN_UNKNOWN="$UNKNOWN_KNOWN"
export SEQUEL_MCP_TEST_SSH_KNOWN_REVOKED="$REVOKED_KNOWN"
export SEQUEL_MCP_TEST_SSH_KNOWN_MALFORMED="$MALFORMED_KNOWN"
export SEQUEL_MCP_TEST_SSH_KNOWN_MISSING="$MISSING_KNOWN"
export SEQUEL_MCP_TEST_SSH_KEY="$KEY_DIR/id_ed25519"
export SEQUEL_MCP_TEST_SSH_MYSQL_CREDS="root:$DB_PASSWORD"

refresh_host_key_fixture() {
  local pub
  pub="$(docker exec "$SSHD_CONTAINER" cat /etc/ssh/ssh_host_ed25519_key.pub \
    | awk '{print $1" "$2}')"
  if [ -z "$pub" ]; then
    echo "failed to re-export host key" >&2
    return 1
  fi
  printf '[127.0.0.1]:%s %s\n' "$SSH_PORT" "$pub" >"$GOOD_KNOWN"
}

# ---- Phase A: bastion up — transport, host-key gates, auth, reuse ----
cargo test --test mysql_ssh -- --test-threads=1 \
  --skip ssh_bastion_death_typed_refusal \
  --skip ssh_bastion_reconnect_after_restart

# ---- Phase B: bastion DOWN — typed, bounded refusal (fresh process) ----
docker stop "$SSHD_CONTAINER" >/dev/null
cargo test --test mysql_ssh ssh_bastion_death_typed_refusal -- \
  --exact --test-threads=1

# ---- Phase C: bastion back — refresh the host-key fixture (independent
# of key-regeneration behaviour) and reconnect through a fresh session --
docker start "$SSHD_CONTAINER" >/dev/null
wait_listening "$SSH_PORT"
refresh_host_key_fixture
cargo test --test mysql_ssh ssh_bastion_reconnect_after_restart -- \
  --exact --test-threads=1

echo "==> SSH transport matrix PASSED"
