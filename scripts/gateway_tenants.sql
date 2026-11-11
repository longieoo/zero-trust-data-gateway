-- v5 migration: idempotent, no deletion of existing rows. Run as migration owner.
BEGIN;
ALTER TABLE customer_data ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'demo';
ALTER TABLE financial_records ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'demo';
ALTER TABLE production_logs ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'demo';
CREATE INDEX IF NOT EXISTS customer_tenant_department ON customer_data(tenant_id, department, id);
CREATE INDEX IF NOT EXISTS financial_tenant_department ON financial_records(tenant_id, department, id);
CREATE INDEX IF NOT EXISTS production_tenant_department ON production_logs(tenant_id, department, id);
-- RESTRICTIVE is AND-ed with all permissive policies, including future grants.
DROP POLICY IF EXISTS gateway_tenant ON customer_data;
CREATE POLICY gateway_tenant ON customer_data AS RESTRICTIVE FOR SELECT TO gateway_reader
 USING (tenant_id = nullif(current_setting('gateway.tenant_id', true), ''));
DROP POLICY IF EXISTS gateway_tenant ON financial_records;
CREATE POLICY gateway_tenant ON financial_records AS RESTRICTIVE FOR SELECT TO gateway_reader
 USING (tenant_id = nullif(current_setting('gateway.tenant_id', true), ''));
DROP POLICY IF EXISTS gateway_tenant ON production_logs;
CREATE POLICY gateway_tenant ON production_logs AS RESTRICTIVE FOR SELECT TO gateway_reader
 USING (tenant_id = nullif(current_setting('gateway.tenant_id', true), ''));
COMMIT;
