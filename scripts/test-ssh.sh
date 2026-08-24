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

# WHAT=mariadb (default) | mysql84 | both. The mysql84 variant enables
# TLS (test CA + server cert for db.internal.test, require_secure_transport)
# so the TLS-over-SSH and MySQL 8.4 caching_sha2 cases run against it.
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
# Encrypted key: the passphrase plays the <conn>::ssh secret role.
ssh-keygen -q -t ed25519 -N "$SSH_PASSWORD" -f "$KEY_DIR/id_enc" -C "sqm-ssh-enc"
# ECDSA key (unencrypted).
ssh-keygen -q -t ecdsa -N "" -f "$KEY_DIR/id_ecdsa" -C "sqm-ssh-ecdsa"
# RSA-4096 (unencrypted): the real-world bastion key shape. Guards the
# russh "rsa" feature — a build without it loads the key and even gets
# USERAUTH_PK_OK, then fails to SIGN, which surfaced as a misleading
# "authentication failed" (0.10.2 incident).
ssh-keygen -q -t rsa -b 4096 -N "" -f "$KEY_DIR/id_rsa" -C "sqm-ssh-rsa"
# Decoy keypair: its public half masquerades as the "known" host key in
# the mismatch fixture.
ssh-keygen -q -t ed25519 -N "" -f "$KEY_DIR/decoy" -C "sqm-decoy"
PUB_KEY="$(cat "$KEY_DIR/id_ed25519.pub" "$KEY_DIR/id_enc.pub" "$KEY_DIR/id_ecdsa.pub" "$KEY_DIR/id_rsa.pub")"

# --- Topology -----------------------------------------------------------
# Private network; the database attached WITHOUT any published port
# (alias "db"); bastion attached to the same network with its SSH port
# published on loopback only. The bastion is a purpose-built alpine
# sshd image (deterministic config: TCP forwarding explicitly enabled,
# password + pubkey auth) so the transport under test is not at the
# mercy of a vendor image's defaults.
docker network create "$NETWORK" >/dev/null

case "$WHAT" in
  both)
    # Two full, independent matrices (fresh topology each).
    bash "$0" mariadb
    bash "$0" mysql84
    echo "==> SSH transport matrix PASSED (both)"
    exit 0
    ;;
  mysql84)
    DB_IMAGE="mysql:8.4"
    DB_TLS=1
    ;;
  *)
    DB_IMAGE="mariadb:11"
    DB_TLS=0
    # Derived image with the bridge tools INSIDE the DB container (the
    # bridge execs `docker exec -i <db> nc|socat …` from the bastion).
    DB_BUILD="$(mktemp -d)"
    printf 'FROM mariadb:11\nRUN apt-get update -qq && apt-get install -qq -y netcat-openbsd socat >/dev/null && rm -rf /var/lib/apt/lists/*\n' \
      >"$DB_BUILD/Dockerfile"
    docker build -q -t "sqm-db-bridge:$STAMP" "$DB_BUILD" >/dev/null
    rm -rf "$DB_BUILD"
    DB_IMAGE="sqm-db-bridge:$STAMP"
    ;;
esac

start_db() {
  if [ "$DB_IMAGE" = "mysql:8.4" ]; then
    {
      printf 'MYSQL_ROOT_PASSWORD=%s\n' "$DB_PASSWORD"
      printf 'MYSQL_DATABASE=app\n'
    } >"$SECRET_FILE"
    docker run -d --name "$DB_CONTAINER" --network "$NETWORK" \
      --network-alias db --env-file "$SECRET_FILE" \
      -v "$TLS_DIR:/etc/mysql/tls:ro" \
      mysql:8.4 \
      --ssl-ca=/etc/mysql/tls/ca-cert.pem \
      --ssl-cert=/etc/mysql/tls/server-cert.pem \
      --ssl-key=/etc/mysql/tls/server-key.pem \
      --require_secure_transport=ON >/dev/null
  else
    {
      printf 'MARIADB_ROOT_PASSWORD=%s\n' "$DB_PASSWORD"
      printf 'MARIADB_DATABASE=app\n'
    } >"$SECRET_FILE"
    docker run -d --name "$DB_CONTAINER" --network "$NETWORK" \
      --network-alias db --env-file "$SECRET_FILE" "$DB_IMAGE" >/dev/null
  fi
  rm -f "$SECRET_FILE"
}

SSHD_BUILD="$(mktemp -d)"
cat >"$SSHD_BUILD/Dockerfile" <<'DOCKER'
# Immutable digest pin (alpine 3.20, resolved 2026-08-22) so the bastion
# base image is byte-stable across runs; the running sshd version is
# printed below.
FROM alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache openssh-server openssh-client iptables docker-cli
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
# The bridge execs `docker exec` as the session user; the TEST bastion
# opens the mounted socket to all (production bastions instead grant
# the SSH user docker-group access — an ops prerequisite for the
# bridge, recorded in VERIFICATION.md).
chmod 666 /var/run/docker.sock 2>/dev/null || true
cat >/etc/ssh/sshd_config <<'SSHD'
Port 2222
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
# Direct-tcpip (local forwarding from the client's view) is the ONLY
# forwarding this bastion exists for; everything else is off.
AllowTcpForwarding local
PermitOpen any
# One multiplexed SSH session carries one channel per MySQL connection;
# concurrent clients need headroom beyond the OpenSSH default of 10.
MaxSessions 64
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
  --cap-add NET_ADMIN \
  -v /var/run/docker.sock:/var/run/docker.sock \
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
    if docker exec "$DB_CONTAINER" mariadb-admin -uroot -p"$DB_PASSWORD" status >/dev/null 2>&1 \
      || docker exec "$DB_CONTAINER" mysqladmin -uroot -p"$DB_PASSWORD" status >/dev/null 2>&1; then
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

# TLS material for the mysql84 variant (test CA + server cert for the
# synthetic name db.internal.test — same recipe as tls-fixtures.sh).
TLS_DIR="$ISO_ROOT/tls"
gen_tls() {
  mkdir -p "$TLS_DIR" && chmod 700 "$TLS_DIR"
  (
    cd "$TLS_DIR"
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout ca-key.pem -out ca-cert.pem -days 1 \
      -subj "/CN=sqm-ssh-ca" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
    openssl req -newkey rsa:2048 -nodes \
      -keyout server-key.pem -out server.csr \
      -subj "/CN=db.internal.test" >/dev/null 2>&1
    printf 'subjectAltName=DNS:db.internal.test\nextendedKeyUsage=serverAuth\n' >server.ext
    openssl x509 -req -in server.csr \
      -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
      -out server-cert.pem -days 1 -extfile server.ext >/dev/null 2>&1
  )
}

if [ "$DB_TLS" = "1" ]; then gen_tls; fi
start_db
export SEQUEL_MCP_TEST_SSH_TLS="$DB_TLS"
if [ "$DB_TLS" = "1" ]; then
  export SEQUEL_MCP_TEST_SSH_TLS_CA="$TLS_DIR/ca-cert.pem"
fi

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
export SEQUEL_MCP_TEST_SSH_KEY_ENC="$KEY_DIR/id_enc"
export SEQUEL_MCP_TEST_SSH_KEY_ECDSA="$KEY_DIR/id_ecdsa"
export SEQUEL_MCP_TEST_SSH_KEY_RSA="$KEY_DIR/id_rsa"
export SEQUEL_MCP_TEST_SSH_MYSQL_CREDS="root:$DB_PASSWORD"
# Rotation + half-open fixtures.
SSH_PASSWORD2="$(head -c 18 /dev/urandom | base64 | tr -d '=+/' | head -c 20)"
export SEQUEL_MCP_TEST_SSH_PASSWORD2="$SSH_PASSWORD2"
export SEQUEL_MCP_TEST_SSH_SENTINEL="$ISO_ROOT/blackhole-now"
# Shorter keepalive so half-open detection runs in seconds (knob is
# clamped 1..=300 in the binary).
export SEQUEL_MCP_SSH_KEEPALIVE_SECS=2

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
  --skip ssh_bastion_reconnect_after_restart \
  --skip ssh_halfopen_stale_session_bounded \
  --skip ssh_blackhole_recovery \
  --skip ssh_rotation_old_credential_rejected

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

# ---- Phase D: packet blackhole (half-open) — DROP all bastion input
# (established AND new), so no FIN/RST ever reaches the client. The
# dropper creates the sentinel right after the rule lands; the test
# holds a live session, waits for the sentinel, and must see the stale
# session fail within a bounded window.
rm -f "$SEQUEL_MCP_TEST_SSH_SENTINEL"
BLACKHOLE_OK=0
if docker exec "$SSHD_CONTAINER" iptables -L >/dev/null 2>&1; then
  BLACKHOLE_OK=1
  echo "==> blackhole via iptables DROP (lands at t+12s)"
  ( sleep 12 \
    && docker exec "$SSHD_CONTAINER" iptables -I INPUT -j DROP \
    && touch "$SEQUEL_MCP_TEST_SSH_SENTINEL" ) &
else
  echo "==> iptables unavailable; falling back to network disconnect"
  ( sleep 12 \
    && docker network disconnect "$NETWORK" "$SSHD_CONTAINER" \
    && touch "$SEQUEL_MCP_TEST_SSH_SENTINEL" ) &
fi
cargo test --test mysql_ssh ssh_halfopen_stale_session_bounded -- \
  --exact --test-threads=1
wait || true
if [ "$BLACKHOLE_OK" = "1" ]; then
  docker exec "$SSHD_CONTAINER" iptables -D INPUT -j DROP >/dev/null 2>&1 || true
else
  docker network connect "$NETWORK" "$SSHD_CONTAINER" 2>/dev/null || true
fi
# Recovery after the blackhole clears.
cargo test --test mysql_ssh ssh_blackhole_recovery -- \
  --exact --test-threads=1

# ---- Phase F: Docker bridge (exec-channel forwarding) — runs with
# AllowTcpForwarding DISABLED so the tests prove traffic flows through
# `docker exec -i <container> nc|socat …` exec channels on the bastion,
# not direct-tcpip. Mariadb variant only: the bridge tools live inside
# the derived DB image; the mysql84+TLS variant exercises the direct
# path (the bridge sits below the MySQL protocol and is engine-agnostic).
if [ "$DB_TLS" != "1" ]; then
export SEQUEL_MCP_TEST_SSH_BRIDGE=1
export SEQUEL_MCP_TEST_SSH_BRIDGE_CONTAINER="$DB_CONTAINER"
docker exec "$SSHD_CONTAINER" sed -i 's/^AllowTcpForwarding local/AllowTcpForwarding no/' /etc/ssh/sshd_config
docker exec "$SSHD_CONTAINER" pkill -HUP sshd || true
sleep 1
echo "==> bridge phase: $(docker exec "$SSHD_CONTAINER" grep -i '^AllowTcpForwarding' /etc/ssh/sshd_config)"
cargo test --test mysql_ssh bridge_ -- --test-threads=1
docker exec "$SSHD_CONTAINER" sed -i 's/^AllowTcpForwarding no/AllowTcpForwarding local/' /etc/ssh/sshd_config
docker exec "$SSHD_CONTAINER" pkill -HUP sshd || true
sleep 1
unset SEQUEL_MCP_TEST_SSH_BRIDGE SEQUEL_MCP_TEST_SSH_BRIDGE_CONTAINER
fi

# ---- Phase G: RSA hash-negotiation pin — restrict the bastion to
# `PubkeyAcceptedAlgorithms rsa-sha2-256` and authenticate with the RSA
# key again. The client must negotiate AND sign with SHA-256; the
# incident's essence was signing without the negotiated hash. If the
# negotiated hash ever stops reaching the signature, sshd rejects it
# here and the test fails. Runs in every variant (engine-agnostic).
docker exec "$SSHD_CONTAINER" sh -c \
  'printf "PubkeyAcceptedAlgorithms rsa-sha2-256\n" >> /etc/ssh/sshd_config'
docker exec "$SSHD_CONTAINER" pkill -HUP sshd || true
sleep 1
echo "==> pin phase: $(docker exec "$SSHD_CONTAINER" grep -i '^PubkeyAcceptedAlgorithms' /etc/ssh/sshd_config)"
export SEQUEL_MCP_TEST_SSH_RSA_PIN="sha2-256"
cargo test --test mysql_ssh ssh_rsa_sha2_256 -- --test-threads=1
unset SEQUEL_MCP_TEST_SSH_RSA_PIN
docker exec "$SSHD_CONTAINER" sed -i '/^PubkeyAcceptedAlgorithms rsa-sha2-256$/d' /etc/ssh/sshd_config
docker exec "$SSHD_CONTAINER" pkill -HUP sshd || true
sleep 1

# ---- Optional bench phase (SSH cold/warm) ----
if [ "${SEQUEL_MCP_TEST_SSH_BENCH:-0}" = "1" ]; then
  cargo test --test mysql_ssh ssh_bench_cold_warm -- --exact --test-threads=1 --nocapture
fi

# ---- Phase E: credential rotation server-side — the OLD password must
# fail authentication (no stale authenticated session reuse).
docker exec "$SSHD_CONTAINER" sh -c \
  "echo '$SSH_USER:$SSH_PASSWORD2' | chpasswd"
cargo test --test mysql_ssh ssh_rotation_old_credential_rejected -- \
  --exact --test-threads=1

echo "==> SSH transport matrix PASSED"
