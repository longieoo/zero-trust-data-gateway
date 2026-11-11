#!/bin/sh
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v session_password="$GATEWAY_SESSION_DB_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE gateway_session LOGIN PASSWORD %L', :'session_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='gateway_session') \gexec
CREATE SCHEMA IF NOT EXISTS gateway_auth;
CREATE TABLE IF NOT EXISTS gateway_auth.sessions (id text PRIMARY KEY, expires bigint NOT NULL);
GRANT CONNECT ON DATABASE gateway_db TO gateway_session;
GRANT USAGE ON SCHEMA gateway_auth TO gateway_session;
GRANT SELECT,INSERT,DELETE ON gateway_auth.sessions TO gateway_session;
SQL
