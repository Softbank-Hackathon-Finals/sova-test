-- Explicit upgrade: preserve migration states, add purpose-specific response states.
ALTER TABLE sova_control.operations DROP CONSTRAINT IF EXISTS operations_status_check;
ALTER TABLE sova_control.operations ADD CONSTRAINT operations_status_check CHECK(status IN (
 'registered','assessing','rehearsing','awaiting_approval','preparing','syncing','cutover_ready',
 'fencing','switching','verifying','stabilizing','service_moved','finalizing','finalized',
 'blocked','failed','cancelled','recovery_required','recovering','recovered',
 'containing','preparing_replacement','verifying_replacement','response_verified'));
CREATE TABLE IF NOT EXISTS sova_control.security_routes (
 tenant_id text NOT NULL, application_id text NOT NULL, route_id text NOT NULL,
 target_environment text NOT NULL, revision bigint NOT NULL DEFAULT 1 CHECK(revision>=1),
 plan_digest text, updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,application_id,route_id)
);
ALTER TABLE sova_control.security_routes ENABLE ROW LEVEL SECURITY;
ALTER TABLE sova_control.security_routes FORCE ROW LEVEL SECURITY;
DO $migration$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='sova_control' AND tablename='security_routes' AND policyname='tenant_scope') THEN
  CREATE POLICY tenant_scope ON sova_control.security_routes
   USING(tenant_id=current_setting('sova.tenant_id',true)) WITH CHECK(tenant_id=current_setting('sova.tenant_id',true));
 END IF;
END
$migration$;
REVOKE ALL ON sova_control.security_routes FROM PUBLIC;
