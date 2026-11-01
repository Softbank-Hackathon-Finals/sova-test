-- Migration owner only. Depends on lifecycle and operations migrations.
CREATE TABLE IF NOT EXISTS sova_control.app_execution (
    tenant_id text NOT NULL, application_id text NOT NULL,
    operation_id text, owner_id text, token text, epoch bigint NOT NULL DEFAULT 0 CHECK(epoch>=0),
    valid_until timestamptz, mode text CHECK(mode IN ('mutate','reconcile')),
    proof_digest text, proof_valid_until timestamptz, recovery_effects jsonb,
    PRIMARY KEY(tenant_id,application_id),
    FOREIGN KEY(tenant_id,application_id,operation_id)
      REFERENCES sova_control.operations(tenant_id,application_id,operation_id),
    CHECK((token IS NULL)=(owner_id IS NULL)),
    CHECK((token IS NULL)=(valid_until IS NULL)),
    CHECK(token IS NULL OR operation_id IS NOT NULL),
    CHECK(token IS NULL OR mode IS NOT NULL),
    CHECK(mode IS DISTINCT FROM 'reconcile' OR (proof_digest IS NOT NULL AND proof_valid_until IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS sova_control.effects (
    tenant_id text NOT NULL, application_id text NOT NULL, environment_id text NOT NULL,
    resource_id text NOT NULL, operation_id text NOT NULL, idempotency_key text NOT NULL,
    fingerprint text NOT NULL CHECK(fingerprint ~ '^[0-9a-f]{64}$'),
    command_document jsonb NOT NULL, status text NOT NULL CHECK(status IN (
      'prepared','in_flight','confirmed_applied','confirmed_not_applied','unknown')),
    revision bigint NOT NULL CHECK(revision>=1), observation_document jsonb,
    PRIMARY KEY(tenant_id,application_id,idempotency_key),
    FOREIGN KEY(tenant_id,application_id,operation_id)
      REFERENCES sova_control.operations(tenant_id,application_id,operation_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS effects_unresolved_resource
    ON sova_control.effects(tenant_id,application_id,environment_id,resource_id)
    WHERE status IN ('prepared','in_flight','unknown');
CREATE TABLE IF NOT EXISTS sova_control.effect_events (
    tenant_id text NOT NULL, application_id text NOT NULL, idempotency_key text NOT NULL,
    revision bigint NOT NULL, status text NOT NULL, observation_document jsonb,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(tenant_id,application_id,idempotency_key,revision),
    FOREIGN KEY(tenant_id,application_id,idempotency_key)
      REFERENCES sova_control.effects(tenant_id,application_id,idempotency_key)
);
CREATE TABLE IF NOT EXISTS sova_control.execution_events (
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id text NOT NULL, application_id text NOT NULL, operation_id text NOT NULL,
    epoch bigint NOT NULL, owner_id text NOT NULL, action text NOT NULL,
    proof_digest text, recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
DO $migration$
DECLARE tab text;
BEGIN
  FOREACH tab IN ARRAY ARRAY['app_execution','effects','effect_events','execution_events'] LOOP
    EXECUTE format('ALTER TABLE sova_control.%I ENABLE ROW LEVEL SECURITY',tab);
    EXECUTE format('ALTER TABLE sova_control.%I FORCE ROW LEVEL SECURITY',tab);
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='sova_control' AND tablename=tab AND policyname='tenant_scope') THEN
      EXECUTE format('CREATE POLICY tenant_scope ON sova_control.%I
        USING(tenant_id=current_setting(''sova.tenant_id'',true))
        WITH CHECK(tenant_id=current_setting(''sova.tenant_id'',true))',tab);
    END IF;
  END LOOP;
END
$migration$;
REVOKE ALL ON sova_control.app_execution,sova_control.effects,sova_control.effect_events,sova_control.execution_events FROM PUBLIC;
