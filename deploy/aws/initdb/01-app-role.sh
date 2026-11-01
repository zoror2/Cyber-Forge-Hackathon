#!/bin/sh
# Runs once, on an empty data volume: the API's restricted runtime role
# (no superuser, cannot bypass row-level security). Migrations grant it access.
set -eu
test "${#CB_APP_DB_PASSWORD}" -ge 20 || { echo "CB_APP_DB_PASSWORD must be 20+ characters" >&2; exit 1; }
psql -v ON_ERROR_STOP=1 -v pw="$CB_APP_DB_PASSWORD" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE configbridge_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD :'pw';
SQL
