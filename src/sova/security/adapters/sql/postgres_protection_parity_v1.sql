-- Separate publishers from assessment writers in deployment role grants.
CREATE TABLE IF NOT EXISTS sova_control.protection_policies (
 tenant_id text NOT NULL,
 application_id text NOT NULL,
 revision bigint NOT NULL CHECK (revision>0),
 digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
 document jsonb NOT NULL,
 published_by text NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (tenant_id,application_id,revision),
 UNIQUE (tenant_id,application_id,digest)
);
CREATE TABLE IF NOT EXISTS sova_control.protection_assessments (
 tenant_id text NOT NULL,
 application_id text NOT NULL,
 digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
 policy_digest text NOT NULL,
 plan_digest text NOT NULL CHECK (plan_digest ~ '^[0-9a-f]{64}$'),
 assessed_at timestamptz NOT NULL,
 document jsonb NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (tenant_id,application_id,digest),
 FOREIGN KEY (tenant_id,application_id,policy_digest)
   REFERENCES sova_control.protection_policies(tenant_id,application_id,digest)
);
ALTER TABLE sova_control.protection_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE sova_control.protection_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE sova_control.protection_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE sova_control.protection_assessments FORCE ROW LEVEL SECURITY;
DO $migration$
DECLARE table_name text;
BEGIN
 FOREACH table_name IN ARRAY ARRAY['protection_policies','protection_assessments'] LOOP
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='sova_control' AND tablename=table_name AND policyname='tenant_scope') THEN
   EXECUTE format('CREATE POLICY tenant_scope ON sova_control.%I USING (tenant_id=current_setting(''sova.tenant_id'',true)) WITH CHECK (tenant_id=current_setting(''sova.tenant_id'',true))',table_name);
  END IF;
 END LOOP;
END
$migration$;
REVOKE ALL ON sova_control.protection_policies,sova_control.protection_assessments FROM PUBLIC;
