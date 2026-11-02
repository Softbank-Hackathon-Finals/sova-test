CREATE TABLE IF NOT EXISTS sova_control.signed_security_evidence (
 tenant_id text NOT NULL, application_id text NOT NULL, evidence_id text NOT NULL,
 issuer_id text NOT NULL, key_id text NOT NULL,
 digest text NOT NULL CHECK(digest ~ '^[0-9a-f]{64}$'), document jsonb NOT NULL,
 stored_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,application_id,evidence_id)
);
ALTER TABLE sova_control.signed_security_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE sova_control.signed_security_evidence FORCE ROW LEVEL SECURITY;
DO $migration$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='sova_control' AND tablename='signed_security_evidence' AND policyname='tenant_scope') THEN
  CREATE POLICY tenant_scope ON sova_control.signed_security_evidence
   USING(tenant_id=current_setting('sova.tenant_id',true)) WITH CHECK(tenant_id=current_setting('sova.tenant_id',true));
 END IF;
END
$migration$;
REVOKE ALL ON sova_control.signed_security_evidence FROM PUBLIC;
