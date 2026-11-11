CREATE TABLE customer_data (
 id integer PRIMARY KEY, department text NOT NULL, name text NOT NULL,
 email text NOT NULL, salary integer NOT NULL, national_id text NOT NULL
);
CREATE TABLE financial_records (
 id integer PRIMARY KEY, department text NOT NULL, period text NOT NULL, revenue integer NOT NULL
);
CREATE TABLE production_logs (
 id integer PRIMARY KEY, department text NOT NULL, event text NOT NULL, severity text NOT NULL
);
INSERT INTO customer_data VALUES
 (1,'marketing','Synthetic Customer A','customer-a@example.test',100000,'DEMO-0001'),
 (2,'marketing','Synthetic Customer B','customer-b@example.test',120000,'DEMO-0002'),
 (3,'risk','Synthetic Customer C','customer-c@example.test',150000,'DEMO-0003');
INSERT INTO financial_records VALUES (1,'finance','2026-Q3',300000),(2,'data','2026-Q3',200000);
INSERT INTO production_logs VALUES (1,'data','Deployment completed','info'),(2,'risk','Risk batch completed','info');
-- Runtime role created by the init script; never use database owner credentials in Gateway.
