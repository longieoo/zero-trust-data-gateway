-- Idempotent migration: preserve all existing demo data.
ALTER TABLE customer_data ENABLE ROW LEVEL SECURITY;
ALTER TABLE customer_data FORCE ROW LEVEL SECURITY;
ALTER TABLE financial_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE financial_records FORCE ROW LEVEL SECURITY;
ALTER TABLE production_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE production_logs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS gateway_scope ON customer_data;
CREATE POLICY gateway_scope ON customer_data FOR SELECT TO gateway_reader
 USING (current_setting('gateway.scope', true) = 'all' OR
        (current_setting('gateway.scope', true) = 'department' AND
         department = current_setting('gateway.department', true)));
DROP POLICY IF EXISTS gateway_scope ON financial_records;
CREATE POLICY gateway_scope ON financial_records FOR SELECT TO gateway_reader
 USING (current_setting('gateway.scope', true) = 'all' OR
        (current_setting('gateway.scope', true) = 'department' AND
         department = current_setting('gateway.department', true)));
DROP POLICY IF EXISTS gateway_scope ON production_logs;
CREATE POLICY gateway_scope ON production_logs FOR SELECT TO gateway_reader
 USING (current_setting('gateway.scope', true) = 'all' OR
        (current_setting('gateway.scope', true) = 'department' AND
         department = current_setting('gateway.department', true)));
