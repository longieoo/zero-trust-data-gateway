#!/bin/sh
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v app_password="$GATEWAY_DB_PASSWORD" <<'SQL'
CREATE ROLE gateway_reader LOGIN PASSWORD :'app_password';
GRANT CONNECT ON DATABASE gateway_db TO gateway_reader;
GRANT USAGE ON SCHEMA public TO gateway_reader;
GRANT SELECT ON customer_data, financial_records, production_logs TO gateway_reader;
SQL
