-- Source APP database only. Install with a distinct statistics-capable owner.
-- Readers receive EXECUTE on this fixed projection, not pg_read_all_stats.
CREATE SCHEMA IF NOT EXISTS sova_publisher_inspection;
REVOKE ALL ON SCHEMA sova_publisher_inspection FROM PUBLIC;
CREATE TABLE IF NOT EXISTS sova_publisher_inspection.reader_bindings (
 reader_oid oid PRIMARY KEY, slot_name text NOT NULL,
 replicator_oid oid NOT NULL, application_name text NOT NULL,
 valid_until timestamptz NOT NULL
);
REVOKE ALL ON sova_publisher_inspection.reader_bindings FROM PUBLIC;
CREATE OR REPLACE FUNCTION sova_publisher_inspection.channel_transport()
RETURNS TABLE (
 slot_name text, database_oid oid, backend_pid integer,
 replicator_oid oid, replicator_name name, application_name text,
 peer_address text, replication_state text,
 encrypted boolean, tls_version text, cipher_bits integer,
 binding_valid_until timestamptz
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $sova$
 SELECT s.slot_name::text,d.oid,r.pid,u.oid,u.rolname,r.application_name,
        pg_catalog.host(r.client_addr),r.state,t.ssl,t.version,t.bits,b.valid_until
 FROM sova_publisher_inspection.reader_bindings b
 JOIN pg_catalog.pg_roles reader ON reader.oid=b.reader_oid
 JOIN pg_catalog.pg_database d ON d.datname=pg_catalog.current_database()
 JOIN pg_catalog.pg_replication_slots s ON s.slot_name=b.slot_name AND s.database=d.datname
 JOIN pg_catalog.pg_stat_replication r ON r.pid=s.active_pid AND r.usesysid=b.replicator_oid AND r.application_name=b.application_name
 JOIN pg_catalog.pg_roles u ON u.oid=r.usesysid
 JOIN pg_catalog.pg_stat_ssl t ON t.pid=r.pid
 WHERE reader.rolname=SESSION_USER AND s.slot_type='logical' AND s.plugin='pgoutput'
   AND b.valid_until>pg_catalog.statement_timestamp()
$sova$;
REVOKE ALL ON FUNCTION sova_publisher_inspection.channel_transport() FROM PUBLIC;
