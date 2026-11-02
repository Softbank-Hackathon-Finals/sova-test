-- Migration owner only. Runtime gets SELECT/INSERT, never UPDATE/DELETE.
CREATE TABLE IF NOT EXISTS sova_control.security_hold_events (
    tenant_id text NOT NULL,
    application_id text NOT NULL,
    hold_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision IN (1,2)),
    event_kind text NOT NULL CHECK (event_kind IN ('opened','released')),
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    document jsonb NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(tenant_id,application_id,hold_id,revision),
    CHECK ((revision=1 AND event_kind='opened') OR (revision=2 AND event_kind='released'))
);
ALTER TABLE sova_control.security_hold_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE sova_control.security_hold_events FORCE ROW LEVEL SECURITY;
DO $migration$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='sova_control'
     AND tablename='security_hold_events' AND policyname='tenant_scope') THEN
  CREATE POLICY tenant_scope ON sova_control.security_hold_events
   USING (tenant_id=current_setting('sova.tenant_id',true))
   WITH CHECK (tenant_id=current_setting('sova.tenant_id',true));
 END IF;
END
$migration$;
REVOKE ALL ON sova_control.security_hold_events FROM PUBLIC;
