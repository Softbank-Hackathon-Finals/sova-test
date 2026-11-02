-- Publisher: SELECT,INSERT. Evidence verifier: SELECT only. Never app/agent writable.
CREATE TABLE IF NOT EXISTS sova_control.verifier_trust_events (
 tenant_id text NOT NULL,
 application_id text NOT NULL,
 issuer_id text NOT NULL,
 key_id text NOT NULL,
 revision bigint NOT NULL CHECK (revision>0),
 digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
 document jsonb NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (tenant_id,application_id,issuer_id,key_id,revision)
);
ALTER TABLE sova_control.verifier_trust_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE sova_control.verifier_trust_events FORCE ROW LEVEL SECURITY;
DO $migration$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='sova_control' AND tablename='verifier_trust_events' AND policyname='tenant_scope') THEN
  CREATE POLICY tenant_scope ON sova_control.verifier_trust_events
   USING (tenant_id=current_setting('sova.tenant_id',true))
   WITH CHECK (tenant_id=current_setting('sova.tenant_id',true));
 END IF;
END
$migration$;
REVOKE ALL ON sova_control.verifier_trust_events FROM PUBLIC;
