-- Explicit qualification setup owner; never executed by the HTTP worker.
CREATE TABLE IF NOT EXISTS sova_control.relocation_receipts (
 tenant_id text NOT NULL, application_id text NOT NULL, operation_id text NOT NULL,
 digest text NOT NULL CHECK(digest ~ '^[a-f0-9]{64}$'), document jsonb NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,application_id,operation_id),
 FOREIGN KEY(tenant_id,application_id,operation_id)
 REFERENCES sova_control.operations(tenant_id,application_id,operation_id)
);
ALTER TABLE sova_control.relocation_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE sova_control.relocation_receipts FORCE ROW LEVEL SECURITY;
DO $migration$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='sova_control'
   AND tablename='relocation_receipts' AND policyname='tenant_scope') THEN
  CREATE POLICY tenant_scope ON sova_control.relocation_receipts
  USING(tenant_id=current_setting('sova.tenant_id',true))
  WITH CHECK(tenant_id=current_setting('sova.tenant_id',true));
 END IF;
END
$migration$;
REVOKE ALL ON sova_control.relocation_receipts FROM PUBLIC;
