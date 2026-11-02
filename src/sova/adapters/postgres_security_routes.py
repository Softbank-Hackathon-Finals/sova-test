"""Local gateway routing CAS; does not implement ALB/DNS or data migration."""

from sova.adapters.postgres_plans import PostgresLifecycleRepository
from sova.domain.contracts import ContractError, identifier, digest
from sova.ports.plans import RecordNotFound, RepositoryConflict


class PostgresSecurityRoutes:
    def __init__(self, connect, *, tenant_id):
        self.tenant_id = identifier(tenant_id)
        self.lifecycle = PostgresLifecycleRepository(connect, tenant_id=tenant_id)

    def register(self, application_id, route_id, environment):
        for value in (application_id, route_id, environment):
            identifier(value)
        with self.lifecycle.transaction() as conn:
            conn.execute(
                """INSERT INTO sova_control.security_routes(tenant_id,application_id,route_id,target_environment) VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                (self.tenant_id, application_id, route_id, environment),
            )
        return self.get(application_id, route_id)

    def get(self, application_id, route_id):
        with self.lifecycle.transaction() as conn:
            row = conn.execute(
                "SELECT target_environment,revision,plan_digest FROM sova_control.security_routes WHERE tenant_id=%s AND application_id=%s AND route_id=%s",
                (self.tenant_id, application_id, route_id),
            ).fetchone()
            if not row:
                raise RecordNotFound("Registered route not found")
            return {"environment_id": row[0], "revision": row[1], "plan_digest": row[2]}

    def switch(
        self,
        application_id,
        route_id,
        *,
        source,
        target,
        expected_revision,
        plan_digest,
    ):
        for value in (application_id, route_id, source, target):
            identifier(value)
        digest(plan_digest)
        if (
            source == target
            or type(expected_revision) is not int
            or expected_revision < 1
        ):
            raise ContractError(
                "Distinct route target and positive CAS revision required"
            )
        with self.lifecycle.transaction() as conn:
            row = conn.execute(
                """UPDATE sova_control.security_routes SET target_environment=%s,revision=revision+1,plan_digest=%s,updated_at=clock_timestamp()
             WHERE tenant_id=%s AND application_id=%s AND route_id=%s AND target_environment=%s AND revision=%s RETURNING revision""",
                (
                    target,
                    plan_digest,
                    self.tenant_id,
                    application_id,
                    route_id,
                    source,
                    expected_revision,
                ),
            ).fetchone()
            if not row:
                raise RepositoryConflict("Route CAS changed; inspect before retry")
        return self.get(application_id, route_id)
