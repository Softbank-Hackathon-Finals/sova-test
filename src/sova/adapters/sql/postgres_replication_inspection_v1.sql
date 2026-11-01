-- Install in the destination APP database by a distinct migration owner.
-- This is not a control-plane migration and grants no app runtime permission.
CREATE SCHEMA IF NOT EXISTS sova_replication_inspection;
REVOKE ALL ON SCHEMA sova_replication_inspection FROM PUBLIC;
CREATE TABLE IF NOT EXISTS sova_replication_inspection.reader_bindings (
    reader_oid oid PRIMARY KEY,
    subscription_oid oid NOT NULL,
    valid_until timestamptz NOT NULL
);
REVOKE ALL ON sova_replication_inspection.reader_bindings FROM PUBLIC;
CREATE OR REPLACE FUNCTION sova_replication_inspection.channel_state()
RETURNS TABLE (
    subscription_oid oid,
    database_oid oid,
    subscription_name name,
    enabled boolean,
    publications text[],
    connection_configuration_digest text,
    binding_valid_until timestamptz
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $sova$
    SELECT s.oid,s.subdbid,s.subname,s.subenabled,s.subpublications,
           pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(s.subconninfo,'UTF8')),'hex'),
           b.valid_until
    FROM pg_catalog.pg_subscription AS s
    JOIN sova_replication_inspection.reader_bindings AS b ON b.subscription_oid=s.oid
    JOIN pg_catalog.pg_roles AS r ON r.oid=b.reader_oid
    WHERE r.rolname=SESSION_USER
      AND s.subdbid=(SELECT d.oid FROM pg_catalog.pg_database AS d WHERE d.datname=pg_catalog.current_database())
      AND b.valid_until>pg_catalog.statement_timestamp()
$sova$;
REVOKE ALL ON FUNCTION sova_replication_inspection.channel_state() FROM PUBLIC;
