-- Apply after v1. All INSERT paths serialize with final completion decisions.
-- No SECURITY DEFINER or table privileges are granted by these functions.
CREATE OR REPLACE FUNCTION sova_control.security_hold_set_key(p_tenant text,p_app text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT
SET search_path=pg_catalog
AS $function$
 SELECT encode(sha256(convert_to(
   '{"app":'||to_json(p_app)::text||',"purpose":"security-hold-set","tenant":'||to_json(p_tenant)::text||'}',
   'UTF8')), 'hex')
$function$;

CREATE OR REPLACE FUNCTION sova_control.serialize_security_hold_insert()
RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog
AS $function$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(sova_control.security_hold_set_key(NEW.tenant_id,NEW.application_id),0));
 RETURN NEW;
END
$function$;
DROP TRIGGER IF EXISTS security_hold_set_serialization ON sova_control.security_hold_events;
CREATE TRIGGER security_hold_set_serialization
 BEFORE INSERT ON sova_control.security_hold_events
 FOR EACH ROW EXECUTE FUNCTION sova_control.serialize_security_hold_insert();
