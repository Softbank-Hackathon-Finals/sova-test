"""Migration-owner installer for a NEW monitor-only DB role.

No login secret is generated. Operator workload identity/login provisioning is
separate. A role is fixed to one registered job/resource; tenant settings alone
cannot grant it another application's records or incident release authority.
"""

from psycopg import sql
from sova.domain.contracts import ContractError, identifier
from sova.monitoring.contracts import MonitorRegistration


def create_monitor_role(conn, role, registration):
    identifier(role, limit=40)
    if not isinstance(registration, MonitorRegistration):
        raise ContractError("Typed monitor role registration required")
    if conn.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)).fetchone():
        raise ContractError(
            "Monitor role must be newly created without inherited grants"
        )
    r = registration
    s = r.scope
    with conn.transaction():
        conn.execute(
            sql.SQL(
                "CREATE ROLE {} NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION"
            ).format(sql.Identifier(role))
        )
        conn.execute(
            sql.SQL("GRANT USAGE ON SCHEMA sova_control TO {}").format(
                sql.Identifier(role)
            )
        )
        tables = (
            "monitor_jobs",
            "monitor_input_sets",
            "monitor_runs",
            "monitor_alerts",
            "security_artifacts_v1",
            "security_artifact_events_v1",
            "security_hold_events",
            "signed_security_evidence",
            "verifier_trust_events",
        )
        tenant = sql.SQL("tenant_id={} AND application_id={}").format(
            sql.Literal(s.tenant_id), sql.Literal(s.application_id)
        )
        for table in tables:
            flags = conn.execute(
                "SELECT relrowsecurity,relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='sova_control' AND c.relname=%s",
                (table,),
            ).fetchone()
            if flags != (True, True):
                raise ContractError(
                    "Forced row security is required before monitor grants"
                )
            conn.execute(
                sql.SQL("GRANT SELECT ON sova_control.{} TO {}").format(
                    sql.Identifier(table), sql.Identifier(role)
                )
            )
            extra = sql.SQL("")
            if table.startswith("monitor_"):
                extra = sql.SQL(" AND job_id={}").format(sql.Literal(r.job_id))
            if table == "security_artifacts_v1":
                extra = sql.SQL(" AND environment_id={} AND resource_id={}").format(
                    sql.Literal(s.environment_id), sql.Literal(s.resource_id)
                )
            if table == "security_hold_events":
                extra = sql.SQL(
                    " AND document->'hold'->'scope'->>'environment_id'={} AND document->'hold'->'scope'->>'resource_id'={}"
                ).format(sql.Literal(s.environment_id), sql.Literal(s.resource_id))
            if table == "signed_security_evidence":
                extra = sql.SQL(
                    " AND document->'evidence'->'scope'->>'environment_id'={} AND document->'evidence'->'scope'->>'resource_id'={}"
                ).format(sql.Literal(s.environment_id), sql.Literal(s.resource_id))
            if table == "security_artifact_events_v1":
                extra = sql.SQL(
                    " AND EXISTS (SELECT 1 FROM sova_control.security_artifacts_v1 a WHERE a.tenant_id=security_artifact_events_v1.tenant_id AND a.application_id=security_artifact_events_v1.application_id AND a.artifact_digest=security_artifact_events_v1.artifact_digest)"
                )
            expression = tenant + extra
            conn.execute(
                sql.SQL(
                    "CREATE POLICY {} ON sova_control.{} AS RESTRICTIVE FOR ALL TO {} USING ({}) WITH CHECK ({})"
                ).format(
                    sql.Identifier("monitor_scope_" + role),
                    sql.Identifier(table),
                    sql.Identifier(role),
                    expression,
                    expression,
                )
            )
        for table in (
            "monitor_runs",
            "monitor_alerts",
            "security_artifacts_v1",
            "security_artifact_events_v1",
            "security_hold_events",
        ):
            conn.execute(
                sql.SQL("GRANT INSERT ON sova_control.{} TO {}").format(
                    sql.Identifier(table), sql.Identifier(role)
                )
            )
        conn.execute(
            sql.SQL(
                "GRANT UPDATE(owner_id,lease_token,lease_until,run_id,next_due) ON sova_control.monitor_jobs TO {}"
            ).format(sql.Identifier(role))
        )
        conn.execute(
            sql.SQL(
                "GRANT UPDATE(outcome,review_digest,finished_at) ON sova_control.monitor_runs TO {}"
            ).format(sql.Identifier(role))
        )
        restrictions = {
            "security_artifacts_v1": "artifact_kind IN ('risk-assessment.v1','continuous-security-review.v1')",
            "security_artifact_events_v1": "event_kind='registered' AND revision=1",
            "security_hold_events": "event_kind='opened' AND revision=1",
        }
        for table, expression in restrictions.items():
            conn.execute(
                sql.SQL(
                    "CREATE POLICY {} ON sova_control.{} AS RESTRICTIVE FOR INSERT TO {} WITH CHECK ({})"
                ).format(
                    sql.Identifier("monitor_insert_" + role),
                    sql.Identifier(table),
                    sql.Identifier(role),
                    sql.SQL(expression),
                )
            )
