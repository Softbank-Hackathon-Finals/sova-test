-- Explicit migration owner only; depends on postgres_lifecycle_v1.sql.
CREATE TABLE IF NOT EXISTS sova_control.operations (
    tenant_id text NOT NULL, application_id text NOT NULL, operation_id text NOT NULL,
    plan_id text NOT NULL, plan_digest text NOT NULL,
    approval_id text NOT NULL, approval_revision bigint NOT NULL CHECK(approval_revision>=1),
    requested_by text NOT NULL, idempotency_key text NOT NULL,
    fingerprint text NOT NULL CHECK(fingerprint ~ '^[0-9a-f]{64}$'),
    status text NOT NULL CHECK(status IN (
      'registered','assessing','rehearsing','awaiting_approval','preparing','syncing',
      'cutover_ready','fencing','switching','verifying','stabilizing','service_moved',
      'finalizing','finalized','blocked','failed','cancelled','recovery_required',
      'recovering','recovered')),
    revision bigint NOT NULL CHECK(revision>=1),
    security_hold boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(tenant_id,application_id,operation_id),
    UNIQUE(tenant_id,application_id,idempotency_key),
    FOREIGN KEY(tenant_id,application_id,plan_id,plan_digest)
      REFERENCES sova_control.plans(tenant_id,application_id,plan_id,digest),
    FOREIGN KEY(tenant_id,application_id,approval_id)
      REFERENCES sova_control.approvals(tenant_id,application_id,approval_id)
);
CREATE TABLE IF NOT EXISTS sova_control.operation_events (
    tenant_id text NOT NULL, application_id text NOT NULL, operation_id text NOT NULL,
    revision bigint NOT NULL CHECK(revision>=1), status text NOT NULL,
    actor_id text NOT NULL, recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(tenant_id,application_id,operation_id,revision),
    FOREIGN KEY(tenant_id,application_id,operation_id)
      REFERENCES sova_control.operations(tenant_id,application_id,operation_id)
);
CREATE TABLE IF NOT EXISTS sova_control.operation_outbox (
    tenant_id text NOT NULL, application_id text NOT NULL, operation_id text NOT NULL,
    event_id text NOT NULL, topic text NOT NULL CHECK(topic='operation.requested.v1'),
    payload jsonb NOT NULL, owner_id text, lease_token text, lease_until timestamptz,
    attempt bigint NOT NULL DEFAULT 0 CHECK(attempt>=0),
    published_at timestamptz, suppressed_at timestamptz,
    publisher_id text, message_id text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(tenant_id,application_id,event_id),
    UNIQUE(tenant_id,application_id,operation_id),
    FOREIGN KEY(tenant_id,application_id,operation_id)
      REFERENCES sova_control.operations(tenant_id,application_id,operation_id),
    CHECK ((lease_token IS NULL)=(lease_until IS NULL)),
    CHECK ((lease_token IS NULL)=(owner_id IS NULL))
);
CREATE INDEX IF NOT EXISTS operation_outbox_pending
    ON sova_control.operation_outbox(tenant_id,application_id,created_at)
    WHERE published_at IS NULL AND suppressed_at IS NULL;
DO $migration$
DECLARE tab text;
BEGIN
  FOREACH tab IN ARRAY ARRAY['operations','operation_events','operation_outbox'] LOOP
    EXECUTE format('ALTER TABLE sova_control.%I ENABLE ROW LEVEL SECURITY',tab);
    EXECUTE format('ALTER TABLE sova_control.%I FORCE ROW LEVEL SECURITY',tab);
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='sova_control'
                    AND tablename=tab AND policyname='tenant_scope') THEN
      EXECUTE format('CREATE POLICY tenant_scope ON sova_control.%I
         USING (tenant_id=current_setting(''sova.tenant_id'',true))
         WITH CHECK (tenant_id=current_setting(''sova.tenant_id'',true))',tab);
    END IF;
  END LOOP;
END
$migration$;
REVOKE ALL ON sova_control.operations,sova_control.operation_events,sova_control.operation_outbox FROM PUBLIC;
