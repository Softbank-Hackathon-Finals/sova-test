-- Explicit owner migration; independent from application database migrations.
-- Trusted program publisher: SELECT,INSERT; worker: SELECT only on these tables.
CREATE TABLE IF NOT EXISTS sova_control.migration_programs (
 tenant_id text NOT NULL, application_id text NOT NULL,
 program_digest text NOT NULL CHECK(program_digest ~ '^[0-9a-f]{64}$'),
 document jsonb NOT NULL, issued_at timestamptz NOT NULL,
 valid_until timestamptz NOT NULL CHECK(valid_until>issued_at),
 created_by text NOT NULL, recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,application_id,program_digest)
);
CREATE TABLE IF NOT EXISTS sova_control.migration_phase_bindings (
 tenant_id text NOT NULL, application_id text NOT NULL,
 plan_id text NOT NULL, plan_digest text NOT NULL,
 program_digest text NOT NULL,
 phase text NOT NULL CHECK(phase IN ('prepare','synchronize','rehearse','quiesce','cutover','postcheck')),
 action_registry_digest text NOT NULL CHECK(action_registry_digest ~ '^[0-9a-f]{64}$'),
 created_by text NOT NULL, recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,application_id,plan_id),
 FOREIGN KEY(tenant_id,application_id,plan_id,plan_digest)
  REFERENCES sova_control.plans(tenant_id,application_id,plan_id,digest),
 FOREIGN KEY(tenant_id,application_id,program_digest)
  REFERENCES sova_control.migration_programs(tenant_id,application_id,program_digest)
);
CREATE TABLE IF NOT EXISTS sova_control.migration_phase_completions (
 tenant_id text NOT NULL, application_id text NOT NULL, operation_id text NOT NULL,
 digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'), document jsonb NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,application_id,operation_id),
 FOREIGN KEY(tenant_id,application_id,operation_id)
  REFERENCES sova_control.operations(tenant_id,application_id,operation_id)
);
DO $migration$
DECLARE tab text;
BEGIN
 FOREACH tab IN ARRAY ARRAY['migration_programs','migration_phase_bindings','migration_phase_completions'] LOOP
  EXECUTE format('ALTER TABLE sova_control.%I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('ALTER TABLE sova_control.%I FORCE ROW LEVEL SECURITY',tab);
  IF NOT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='sova_control' AND tablename=tab AND policyname='tenant_scope') THEN
   EXECUTE format('CREATE POLICY tenant_scope ON sova_control.%I USING(tenant_id=current_setting(''sova.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''sova.tenant_id'',true))',tab);
  END IF;
 END LOOP;
END
$migration$;
REVOKE ALL ON sova_control.migration_programs,sova_control.migration_phase_bindings,sova_control.migration_phase_completions FROM PUBLIC;
-- A phase completion never claims that the entire service has moved.
ALTER TABLE sova_control.operations DROP CONSTRAINT IF EXISTS operations_status_check;
ALTER TABLE sova_control.operations ADD CONSTRAINT operations_status_check CHECK(status IN (
 'registered','assessing','rehearsing','awaiting_approval','preparing','syncing','cutover_ready',
 'fencing','switching','verifying','stabilizing','service_moved','finalizing','finalized',
 'blocked','failed','cancelled','recovery_required','recovering','recovered',
 'containing','preparing_replacement','verifying_replacement','response_verified',
 'phase_running','phase_verified'));
