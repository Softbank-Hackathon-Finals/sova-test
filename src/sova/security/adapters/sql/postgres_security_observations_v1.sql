-- Migration owner only. Security readers need SELECT; recorders SELECT/INSERT.
CREATE TABLE IF NOT EXISTS sova_control.security_snapshots (
 tenant_id text NOT NULL, application_id text NOT NULL, environment_id text NOT NULL,
 digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
 graph_digest text NOT NULL CHECK (graph_digest ~ '^[0-9a-f]{64}$'),
 observed_at timestamptz NOT NULL, valid_until timestamptz NOT NULL,
 document jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,application_id,digest), CHECK(valid_until>observed_at)
);
CREATE INDEX IF NOT EXISTS security_snapshots_latest ON sova_control.security_snapshots
 (tenant_id,application_id,environment_id,observed_at DESC);
CREATE TABLE IF NOT EXISTS sova_control.security_event_log (
 sequence bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
 tenant_id text NOT NULL, application_id text NOT NULL, event_id text NOT NULL,
 snapshot_digest text NOT NULL, digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
 document jsonb NOT NULL, stored_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,application_id,event_id),
 FOREIGN KEY(tenant_id,application_id,snapshot_digest)
   REFERENCES sova_control.security_snapshots(tenant_id,application_id,digest)
);
DO $migration$
DECLARE tab text;
BEGIN
 FOREACH tab IN ARRAY ARRAY['security_snapshots','security_event_log'] LOOP
  EXECUTE format('ALTER TABLE sova_control.%I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('ALTER TABLE sova_control.%I FORCE ROW LEVEL SECURITY',tab);
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='sova_control' AND tablename=tab AND policyname='tenant_scope') THEN
   EXECUTE format('CREATE POLICY tenant_scope ON sova_control.%I USING (tenant_id=current_setting(''sova.tenant_id'',true)) WITH CHECK (tenant_id=current_setting(''sova.tenant_id'',true))',tab);
  END IF;
  EXECUTE format('REVOKE ALL ON sova_control.%I FROM PUBLIC',tab);
 END LOOP;
END
$migration$;
REVOKE ALL ON SEQUENCE sova_control.security_event_log_sequence_seq FROM PUBLIC;
