#!/usr/bin/env bash
# Real-Docker lab for "Bring data from another database" (src/dbimport.ts).
# A PostgreSQL 17 "outside" server holds an app's tables; the app's database here (Postgres 16, created
# by PaaSMCP, already migrated with other rows) receives them. Checks: rows arrive, objects belong to the
# app's user, a failed copy changes nothing, errors never show the password.
# Run: sudo env PATH=$PATH scripts/dbimport-lab.sh   (needs Docker; pulls postgres:16 and postgres:17)
set -euo pipefail
cd "$(dirname "$0")/.."
npm run build --silent

ROOT="$(mktemp -d)"
export PAASMCP_ROOT="$ROOT"
SRC=paasmcp-lab-src17
PASS="lab-Pass-$RANDOM"
cleanup() {
  docker rm -f "$SRC" paasmcp-postgres >/dev/null 2>&1 || true
  docker volume ls -q | grep -E '^paasmcp' | xargs -r docker volume rm >/dev/null 2>&1 || true
  rm -rf "$ROOT"
}
trap cleanup EXIT
ok() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*"; exit 1; }

echo "1. Outside server (PostgreSQL 17) with an app's tables"
docker rm -f "$SRC" >/dev/null 2>&1 || true
docker run -d --name "$SRC" -e POSTGRES_PASSWORD="$PASS" -e POSTGRES_DB=guar postgres:17-alpine >/dev/null
for _ in $(seq 1 60); do docker exec "$SRC" pg_isready -U postgres -d guar >/dev/null 2>&1 && break; sleep 1; done
sleep 2
docker exec -i "$SRC" psql -q -U postgres -d guar -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE TABLE notes (id serial PRIMARY KEY, title text NOT NULL, body text);
CREATE TABLE django_migrations (id serial PRIMARY KEY, app text, name text);
INSERT INTO notes (title, body) SELECT 'note ' || g, repeat('x', 50) FROM generate_series(1, 500) g;
INSERT INTO django_migrations (app, name) VALUES ('notes', '0001_initial'), ('notes', '0002_body');
CREATE INDEX notes_title ON notes (title);
COMMENT ON SCHEMA public IS 'standard public schema';
CREATE SCHEMA auth; CREATE TABLE auth.users (id int);
SQL
SRC_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SRC")"
ok "500 notes on $SRC_IP"

echo "2. The app's database here (created by PaaSMCP, already migrated, other rows)"
node -e '
  import("./dist/database.js").then((d) => { d.provisionDatabase("move-lab", "postgres"); });
'
for _ in $(seq 1 60); do docker exec paasmcp-postgres pg_isready -U paasmcp_admin >/dev/null 2>&1 && break; sleep 1; done
docker exec -i paasmcp-postgres psql -q -U user_move_lab -d db_move_lab -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE TABLE notes (id serial PRIMARY KEY, title text NOT NULL, body text);
CREATE TABLE django_migrations (id serial PRIMARY KEY, app text, name text);
INSERT INTO notes (title) VALUES ('only here');
SQL
ok "db_move_lab has 1 row"

echo "3. A wrong password: refused, nothing changed, password never shown"
set +e
OUT="$(node -e '
  import("./dist/dbimport.js").then((m) => m.importExternalPostgres("move-lab", process.argv[1]))
    .then(() => console.log("UNEXPECTED"), (e) => console.log(e.message));
' "postgres://postgres:wrong-$PASS@$SRC_IP:5432/guar?sslmode=disable" 2>&1)"
set -e
echo "$OUT" | grep -q "Could not connect" || fail "expected a connection error, got: $OUT"
echo "$OUT" | grep -q "$PASS" && fail "the password showed up in the error"
[ "$(docker exec paasmcp-postgres psql -XAtq -U user_move_lab -d db_move_lab -c 'select count(*) from notes')" = "1" ] || fail "data changed"
ok "refused in plain words; still 1 row"

echo "4. A copy that fails halfway (a column type unknown here): all or nothing"
docker exec -i "$SRC" psql -q -U postgres -d guar -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE EXTENSION IF NOT EXISTS hstore SCHEMA public;
CREATE TABLE zz_tags (id int, tags hstore);
SQL
set +e
OUT="$(node -e '
  import("./dist/dbimport.js").then((m) => m.importExternalPostgres("move-lab", process.argv[1]))
    .then(() => console.log("UNEXPECTED"), (e) => console.log(e.message));
' "postgres://postgres:$PASS@$SRC_IP:5432/guar?sslmode=disable" 2>&1)"
set -e
echo "$OUT" | grep -q "nothing was changed" || fail "expected a write failure, got: $OUT"
echo "$OUT" | grep -q "$PASS" && fail "the password showed up in the error"
[ "$(docker exec paasmcp-postgres psql -XAtq -U user_move_lab -d db_move_lab -c 'select count(*) from notes')" = "1" ] || fail "a failed copy changed data"
ok "failed copy left the 1 row as it was"
docker exec "$SRC" psql -q -U postgres -d guar -c 'DROP TABLE zz_tags; DROP EXTENSION hstore;' >/dev/null

echo "5. The real copy (17 → 16)"
RES="$(node -e '
  import("./dist/dbimport.js").then((m) => m.importExternalPostgres("move-lab", process.argv[1]))
    .then((r) => console.log(JSON.stringify(r)), (e) => { console.log("ERR " + e.message); process.exit(1); });
' "postgres://postgres:$PASS@$SRC_IP:5432/guar?sslmode=disable")"
echo "  $RES"
echo "$RES" | grep -q '"tables":2' || fail "expected 2 tables"
echo "$RES" | grep -q '"safetyBackupId":"' || fail "no backup from before"
[ "$(docker exec paasmcp-postgres psql -XAtq -U user_move_lab -d db_move_lab -c 'select count(*) from notes')" = "500" ] || fail "rows did not arrive"
[ "$(docker exec paasmcp-postgres psql -XAtq -U user_move_lab -d db_move_lab -c "select count(*) from notes where title = 'only here'")" = "0" ] || fail "old rows stayed"
OWN="$(docker exec paasmcp-postgres psql -XAtq -U paasmcp_admin -d db_move_lab -c "select string_agg(distinct tableowner, ',') from pg_tables where schemaname = 'public'")"
[ "$OWN" = "user_move_lab" ] || fail "tables belong to $OWN"
[ "$(docker exec paasmcp-postgres psql -XAtq -U paasmcp_admin -d db_move_lab -c "select count(*) from pg_namespace where nspname = 'auth'")" = "0" ] || fail "other schemas came along"
docker exec paasmcp-postgres psql -XAtq -U user_move_lab -d db_move_lab -c "insert into notes (title) values ('after'); alter table notes add column extra int;" >/dev/null || fail "the app's user cannot write or migrate"
ok "500 rows, owned by the app's user, only public, app can still migrate"

echo "All dbimport lab checks passed."
