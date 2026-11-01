-- Apply as a migration owner, never as the API runtime role.
CREATE SCHEMA IF NOT EXISTS sova_control;
CREATE TABLE IF NOT EXISTS sova_control.plans (
    tenant_id text NOT NULL, application_id text NOT NULL, plan_id text NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'), document jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(tenant_id,application_id,plan_id),
    UNIQUE(tenant_id,application_id,plan_id,digest)
);
CREATE TABLE IF NOT EXISTS sova_control.inspections (
    tenant_id text NOT NULL, application_id text NOT NULL, inspection_id text NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'), document jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(tenant_id,application_id,inspection_id)
);
CREATE TABLE IF NOT EXISTS sova_control.approvals (
    tenant_id text NOT NULL, application_id text NOT NULL, approval_id text NOT NULL,
    plan_id text NOT NULL, plan_digest text NOT NULL, document jsonb NOT NULL,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1), revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(tenant_id,application_id,approval_id),
    FOREIGN KEY(tenant_id,application_id,plan_id,plan_digest)
      REFERENCES sova_control.plans(tenant_id,application_id,plan_id,digest)
);
CREATE TABLE IF NOT EXISTS sova_control.lifecycle_audit (
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id text NOT NULL, application_id text NOT NULL,
    record_id text NOT NULL, action text NOT NULL, actor_id text NOT NULL,
    revision bigint NOT NULL, recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
DO $migration$
DECLARE tab text;
BEGIN
  FOREACH tab IN ARRAY ARRAY['plans','inspections','approvals','lifecycle_audit'] LOOP
    EXECUTE format('ALTER TABLE sova_control.%I ENABLE ROW LEVEL SECURITY', tab);
    EXECUTE format('ALTER TABLE sova_control.%I FORCE ROW LEVEL SECURITY', tab);
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='sova_control'
                   AND tablename=tab AND policyname='tenant_scope') THEN
      EXECUTE format('CREATE POLICY tenant_scope ON sova_control.%I
        USING (tenant_id = current_setting(''sova.tenant_id'', true))
        WITH CHECK (tenant_id = current_setting(''sova.tenant_id'', true))',tab);
    END IF;
  END LOOP;
END
$migration$;
REVOKE ALL ON SCHEMA sova_control FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA sova_control FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA sova_control FROM PUBLIC;
