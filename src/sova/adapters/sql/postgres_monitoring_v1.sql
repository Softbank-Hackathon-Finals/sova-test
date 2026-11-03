-- Explicit migration owner. Runtime uses non-owner NOBYPASSRLS roles.
CREATE TABLE IF NOT EXISTS sova_control.monitor_jobs (
 tenant_id text NOT NULL, application_id text NOT NULL, job_id text NOT NULL,
 digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'), document jsonb NOT NULL,
 next_due timestamptz NOT NULL, valid_until timestamptz NOT NULL,
 enabled boolean NOT NULL DEFAULT true, owner_id text, lease_token text,
 lease_until timestamptz, run_id text,
 PRIMARY KEY(tenant_id,application_id,job_id),
 CHECK((lease_token IS NULL)=(lease_until IS NULL)),
 CHECK((lease_token IS NULL)=(owner_id IS NULL)),
 CHECK((lease_token IS NULL)=(run_id IS NULL))
);
CREATE TABLE IF NOT EXISTS sova_control.monitor_runs (
 tenant_id text NOT NULL, application_id text NOT NULL, job_id text NOT NULL,
 run_id text NOT NULL, outcome text NOT NULL CHECK(outcome IN ('running','observed','attention','failed','abandoned')),
 review_digest text CHECK(review_digest ~ '^[0-9a-f]{64}$'),
 started_at timestamptz NOT NULL DEFAULT clock_timestamp(), finished_at timestamptz,
 PRIMARY KEY(tenant_id,application_id,job_id,run_id),
 FOREIGN KEY(tenant_id,application_id,job_id) REFERENCES sova_control.monitor_jobs
);
CREATE TABLE IF NOT EXISTS sova_control.monitor_alerts (
 tenant_id text NOT NULL, application_id text NOT NULL, job_id text NOT NULL,
 run_id text NOT NULL, alert_id text NOT NULL,
 category text NOT NULL CHECK(category IN ('monitor_failed','security_attention','monitor_abandoned')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 owner_id text, lease_token text, lease_until timestamptz,
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 8),
 delivered_at timestamptz, sink_id text, receipt_id text,
 PRIMARY KEY(tenant_id,application_id,alert_id),
 UNIQUE(tenant_id,application_id,job_id,run_id),
 FOREIGN KEY(tenant_id,application_id,job_id,run_id) REFERENCES sova_control.monitor_runs,
 CHECK((lease_token IS NULL)=(lease_until IS NULL)),
 CHECK((lease_token IS NULL)=(owner_id IS NULL))
);
CREATE INDEX IF NOT EXISTS monitor_due ON sova_control.monitor_jobs(tenant_id,next_due) WHERE enabled;
CREATE INDEX IF NOT EXISTS monitor_alert_pending ON sova_control.monitor_alerts(tenant_id,application_id,created_at) WHERE delivered_at IS NULL;
DO $migration$
DECLARE tab text;
BEGIN
 FOREACH tab IN ARRAY ARRAY['monitor_jobs','monitor_runs','monitor_alerts'] LOOP
  EXECUTE format('ALTER TABLE sova_control.%I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('ALTER TABLE sova_control.%I FORCE ROW LEVEL SECURITY',tab);
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='sova_control' AND tablename=tab AND policyname='tenant_scope') THEN
   EXECUTE format('CREATE POLICY tenant_scope ON sova_control.%I USING (tenant_id=current_setting(''sova.tenant_id'',true)) WITH CHECK (tenant_id=current_setting(''sova.tenant_id'',true))',tab);
  END IF;
 END LOOP;
END
$migration$;
REVOKE ALL ON sova_control.monitor_jobs,sova_control.monitor_runs,sova_control.monitor_alerts FROM PUBLIC;
CREATE TABLE IF NOT EXISTS sova_control.monitor_input_sets (
 tenant_id text NOT NULL, application_id text NOT NULL, job_id text NOT NULL,
 revision bigint NOT NULL CHECK(revision>=1), digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'),
 document jsonb NOT NULL, recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,application_id,job_id,revision),
 UNIQUE(tenant_id,application_id,job_id,digest),
 FOREIGN KEY(tenant_id,application_id,job_id) REFERENCES sova_control.monitor_jobs
);
ALTER TABLE sova_control.monitor_input_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE sova_control.monitor_input_sets FORCE ROW LEVEL SECURITY;
DO $migration$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='sova_control' AND tablename='monitor_input_sets' AND policyname='tenant_scope') THEN
 CREATE POLICY tenant_scope ON sova_control.monitor_input_sets
  USING(tenant_id=current_setting('sova.tenant_id',true)) WITH CHECK(tenant_id=current_setting('sova.tenant_id',true));
 END IF;
END
$migration$;
REVOKE ALL ON sova_control.monitor_input_sets FROM PUBLIC;
