#!/usr/bin/env bash
# Deterministic database test lifecycle: unique network + containers,
# synthetic credentials generated per run, health wait, test execution,
# full cleanup via trap. Credentials live only in a 0600 env-file passed
# to docker and in the test process environment — never in the repo or logs.
#
# Usage:
#   scripts/test-db.sh mariadb            # run integration tests vs MariaDB 11
#   scripts/test-db.sh mysql              # run integration tests vs MySQL 8.4
#   scripts/test-db.sh both               # both matrices
set -euo pipefail
cd "$(dirname "$0")/.."

WHAT="${1:-mariadb}"
STAMP="$(date +%s)-$$"
NETWORK="sqm-test-net-$STAMP"
MARIADB_CONTAINER="sqm-mariadb-$STAMP"
MYSQL_CONTAINER="sqm-mysql-$STAMP"

# Runtime-generated synthetic credential material (never a literal here).
SECRET_FILE="$(mktemp)"
chmod 600 "$SECRET_FILE"
DB_PASSWORD="$(head -c 18 /dev/urandom | base64 | tr -d '=+/' | head -c 20)"

cleanup() {
  local rc=$?
  docker rm -f "$MARIADB_CONTAINER" "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  rm -f "$SECRET_FILE"
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

wait_healthy() {
  local container="$1" user="$2" tries=120 consecutive=0
  # MySQL/MariaDB entrypoints run a temporary init server first; a probe
  # can succeed against it and then fail when it restarts. Require several
  # consecutive successes before declaring healthy.
  for _ in $(seq 1 $tries); do
    if docker exec "$container" mariadb-admin -u"$user" -p"$DB_PASSWORD" status >/dev/null 2>&1 \
      || docker exec "$container" mysqladmin -u"$user" -p"$DB_PASSWORD" status >/dev/null 2>&1; then
      consecutive=$((consecutive + 1))
      if [ "$consecutive" -ge 5 ]; then
        return 0
      fi
    else
      consecutive=0
    fi
    sleep 1
  done
  echo "container $container failed to become healthy" >&2
  return 1
}

run_matrix() {
  local flavor="$1" image="$2" container="$3" port="$4" user="$5"
  # Container bootstrap env (synthetic, per-run) via a private env-file.
  {
    printf 'MARIADB_ROOT_PASSWORD=%s\n' "$DB_PASSWORD"
    printf 'MYSQL_ROOT_PASSWORD=%s\n' "$DB_PASSWORD"
    printf 'MARIADB_DATABASE=app\n'
    printf 'MYSQL_DATABASE=app\n'
  } >"$SECRET_FILE"
  docker run -d --name "$container" --network "$NETWORK" \
    --env-file "$SECRET_FILE" -p "$port":3306 "$image" >/dev/null
  wait_healthy "$container" "$user"
  rm -f "$SECRET_FILE"
  echo "==> $flavor ready on 127.0.0.1:$port (container $container)"
  SEQUEL_MCP_TEST_MYSQL="127.0.0.1:$port:$user:$DB_PASSWORD" \
    cargo test --test mysql_integration --test repro_block -- --test-threads=1
  SEQUEL_MCP_TEST_MYSQL="127.0.0.1:$port:$user:$DB_PASSWORD" \
    cargo test --test mysql_matrix --test mysql_d1 --test mysql_d2 --test mysql_d3 -- --test-threads=1
  docker rm -f "$container" >/dev/null
}

# One shared network per script invocation; both matrices reuse it.
docker network create "$NETWORK" >/dev/null

case "$WHAT" in
  mariadb)
    run_matrix "MariaDB 11" mariadb:11 "$MARIADB_CONTAINER" "$(pick_port)" root
    ;;
  mysql)
    run_matrix "MySQL 8.4" mysql:8.4 "$MYSQL_CONTAINER" "$(pick_port)" root
    ;;
  both)
    run_matrix "MariaDB 11" mariadb:11 "$MARIADB_CONTAINER" "$(pick_port)" root
    run_matrix "MySQL 8.4" mysql:8.4 "$MYSQL_CONTAINER" "$(pick_port)" root
    ;;
  *)
    echo "usage: $0 {mariadb|mysql|both}" >&2
    exit 2
    ;;
esac

echo "==> $WHAT matrix PASSED"
