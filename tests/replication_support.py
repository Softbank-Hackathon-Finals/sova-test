"""Disposable logical-replication fixture. Never used by the product executor."""

from contextlib import contextmanager
from dataclasses import dataclass, replace, field
from datetime import UTC, datetime, timedelta
import time
import hashlib
import os
from pathlib import Path
import secrets
from uuid import uuid4

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo
import pytest

from sova.adapters.postgres_dataset import (
    table_definition,
    PostgresDatasetRegistration,
    PostgresDatasetReader,
)
from sova.adapters.postgres_replication import (
    ReplicationEndpoint,
    ReplicatedTable,
    ReplicationRegistration,
    PostgresReplicationObserver,
)
from sova.domain.contracts import ResourceScope
from sova.domain.evidence import RevisionSet
from sova.adapters.postgres_channel_inspection import install_channel_inspector
from sova.adapters.postgres_publisher_inspection import install_publisher_inspector


def replication_connection(dsn, role, application_name, password, root_ca):
    if root_ca is None:
        return make_conninfo(dsn, user=role, application_name=application_name)
    from psycopg.conninfo import conninfo_to_dict

    values = conninfo_to_dict(dsn)
    return make_conninfo(
        host="localhost",
        hostaddr="127.0.0.1",
        port=values["port"],
        dbname=values["dbname"],
        user=role,
        password=password,
        sslmode="verify-full",
        sslrootcert=root_ca,
        application_name=application_name,
    )


def wait_for(check, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError(
        "Own bounded logical replication fixture did not reach expected state"
    )


@dataclass
class LogicalPair:
    dsns: dict
    roles: dict
    registration: ReplicationRegistration
    users: object
    reverse_pair: object = None
    reverse_names: dict | None = None
    _replication_password: str | None = field(default=None, repr=False)
    _root_ca: str | None = field(default=None, repr=False)

    def publisher_connection(self, side, application_name):
        return replication_connection(
            self.dsns[side],
            self.roles["replicator"],
            application_name,
            self._replication_password,
            self._root_ca,
        )

    def reader(self, side, table):
        endpoint = getattr(self.registration, side)
        with psycopg.connect(self.dsns[side], autocommit=True) as owner:
            definition = table_definition(owner, *table)
        reg = PostgresDatasetRegistration(
            endpoint.scope,
            self.registration.revisions,
            endpoint.connection_ref,
            endpoint.database_name,
            endpoint.database_oid,
            endpoint.system_identifier,
            endpoint.reader_role,
            *table,
            definition["table_oid"],
            definition["schema_digest"],
            definition["columns"],
            definition["primary_key"],
            self.registration.issued_at,
            self.registration.valid_until,
            allow_private_unix_fixture=True,
        )
        return reg, lambda ref: psycopg.connect(
            self.dsns[side], user=endpoint.reader_role
        )

    def manifest(self, side, table, boundary):
        reg, connect = self.reader(side, table)
        return PostgresDatasetReader(
            reg,
            connect=connect,
            authorize=lambda *args: None,
            authenticate_registration=lambda _: None,
            clock=lambda: datetime.now(UTC),
            monotonic=time.monotonic,
        ).snapshot("fixture-operator", boundary_id=boundary)["manifest"]

    def barrier(self, *, boundary, plan, epoch):
        r = self.registration
        with psycopg.connect(self.dsns["source"], autocommit=True) as owner:
            owner.execute(
                sql.SQL("INSERT INTO {}.{} VALUES(%s,%s,%s)").format(
                    sql.Identifier(r.barrier_schema), sql.Identifier(r.barrier_table)
                ),
                (boundary, plan, epoch),
            )
        with psycopg.connect(self.dsns["target"], autocommit=True) as target:
            wait_for(
                lambda: target.execute(
                    sql.SQL("SELECT 1 FROM {}.{} WHERE boundary_id=%s").format(
                        sql.Identifier(r.barrier_schema),
                        sql.Identifier(r.barrier_table),
                    ),
                    (boundary,),
                ).fetchone()
            )

    def observe(self, *, boundary, plan, epoch):
        r = self.registration
        refs = {
            endpoint.connection_ref: make_conninfo(
                self.dsns[side], user=endpoint.reader_role
            )
            for side, endpoint in (("source", r.source), ("target", r.target))
        }
        return PostgresReplicationObserver(
            r,
            connect=lambda ref: psycopg.connect(refs[ref]),
            authorize=lambda *args: None,
            authenticate_registration=lambda _: None,
            clock=lambda: datetime.now(UTC),
            monotonic=time.monotonic,
        ).inspect(
            "fixture-operator",
            boundary_id=boundary,
            plan_digest=plan,
            writer_epoch=epoch,
        )

    def pause_subscription(self):
        r = self.registration
        with psycopg.connect(self.dsns["target"], autocommit=True) as owner:
            owner.execute(
                sql.SQL("ALTER SUBSCRIPTION {} DISABLE").format(
                    sql.Identifier(r.subscription)
                )
            )
            wait_for(
                lambda: owner.execute(
                    "SELECT count(*)=0 FROM pg_catalog.pg_stat_subscription WHERE subid=%s AND pid IS NOT NULL",
                    (r.subscription_oid,),
                ).fetchone()[0]
            )

    def prepare_reverse(self):
        """Test-only: caller already fenced source and compared all datasets.

        Create the reverse slot before opening the new writer. copy_data=false
        assumes the frozen baseline is equal; origin=none avoids echoing earlier
        forward-replicated changes. The original subscription must stay drained.
        """
        r = self.registration
        if self.reverse_names is not None:
            raise AssertionError("Reverse channel already prepared")
        with psycopg.connect(self.dsns["target"], autocommit=True) as owner:
            enabled = owner.execute(
                "SELECT subenabled FROM pg_subscription WHERE oid=%s",
                (r.subscription_oid,),
            ).fetchone()
            assert enabled == (False,)
            assert owner.execute(
                "SELECT count(*) FROM pg_stat_subscription WHERE subid=%s AND pid IS NOT NULL",
                (r.subscription_oid,),
            ).fetchone() == (0,)
        suffix = uuid4().hex
        names = {
            key: "reverse_" + key + "_" + suffix
            for key in ("publication", "subscription", "slot")
        }
        self.reverse_names = names
        tables = tuple((t.schema, t.table) for t in r.tables)
        with psycopg.connect(self.dsns["target"], autocommit=True) as publisher:
            for schema in {s for s, _ in tables}:
                publisher.execute(
                    sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                        sql.Identifier(schema), sql.Identifier(self.roles["replicator"])
                    )
                )
                publisher.execute(
                    sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA {} TO {}").format(
                        sql.Identifier(schema), sql.Identifier(self.roles["replicator"])
                    )
                )
            publisher.execute(
                sql.SQL("CREATE PUBLICATION {} FOR TABLE {}").format(
                    sql.Identifier(names["publication"]),
                    sql.SQL(",").join(
                        sql.SQL("{}.{}").format(sql.Identifier(s), sql.Identifier(t))
                        for s, t in tables
                    ),
                )
            )
            puboid = publisher.execute(
                "SELECT oid FROM pg_publication WHERE pubname=%s",
                (names["publication"],),
            ).fetchone()[0]
            publisher.execute(
                "SELECT pg_create_logical_replication_slot(%s,'pgoutput')",
                (names["slot"],),
            )
        approved = self.publisher_connection("target", names["subscription"])
        with psycopg.connect(self.dsns["source"], autocommit=True) as subscriber:
            subscriber.execute(
                sql.SQL(
                    "CREATE SUBSCRIPTION {} CONNECTION {} PUBLICATION {} WITH(create_slot=false,slot_name={},copy_data=false,origin=none)"
                ).format(
                    sql.Identifier(names["subscription"]),
                    sql.Literal(approved),
                    sql.Identifier(names["publication"]),
                    sql.Literal(names["slot"]),
                )
            )
            suboid = subscriber.execute(
                "SELECT oid FROM pg_subscription WHERE subname=%s",
                (names["subscription"],),
            ).fetchone()[0]
            subscriber.execute(
                sql.SQL(
                    "GRANT SELECT(oid,subdbid,subname,subenabled,subpublications) ON pg_catalog.pg_subscription TO {}"
                ).format(sql.Identifier(r.source.reader_role))
            )
            wait_for(
                lambda: subscriber.execute(
                    "SELECT count(*)=%s AND bool_and(srsubstate='r') FROM pg_subscription_rel WHERE srsubid=%s",
                    (len(tables), suboid),
                ).fetchone()[0]
            )
            inspector = install_channel_inspector(
                subscriber,
                reader_role=r.source.reader_role,
                subscription_oid=suboid,
                expected_connection_digest=hashlib.sha256(
                    approved.encode()
                ).hexdigest(),
                valid_until=r.valid_until,
                expected_slot_name=names["slot"],
            )
        reverse = ReplicationRegistration(
            r.target,
            r.source,
            r.revisions,
            names["publication"],
            puboid,
            names["subscription"],
            suboid,
            tuple(
                replace(t, source_oid=t.target_oid, target_oid=t.source_oid)
                for t in r.tables
            ),
            r.barrier_schema,
            r.barrier_table,
            r.issued_at,
            r.valid_until,
            inspector=inspector,
        )
        if self._root_ca is not None:
            with psycopg.connect(self.dsns["target"], autocommit=True) as owner:
                publisher = install_publisher_inspector(
                    owner,
                    reader_role=r.target.reader_role,
                    slot_name=names["slot"],
                    replicator_role=self.roles["replicator"],
                    application_name=names["subscription"],
                    expected_peer_addresses=("127.0.0.1",),
                    valid_until=r.valid_until,
                )
            reverse = replace(reverse, publisher_inspector=publisher)
        self.reverse_pair = LogicalPair(
            {"source": self.dsns["target"], "target": self.dsns["source"]},
            self.roles,
            reverse,
            None,
            _replication_password=self._replication_password,
            _root_ca=self._root_ca,
        )
        return self.reverse_pair


@contextmanager
def logical_pair(
    base, *, tables, source_setup, target_setup, target_base=None, tls_replication=False
):
    root_ca = None
    password = None
    if tls_replication:
        if not os.environ.get("SOVA_TEST_POSTGRES_TLS_ROOT"):
            pytest.skip(
                "Explicit native TLS fixture required for replication transport"
            )
        root_ca = str(Path(os.environ["SOVA_TEST_POSTGRES_TLS_ROOT"]) / "ca.pem")
        password = secrets.token_urlsafe(32)
    unique = uuid4().hex
    names = {
        key: key + "_" + unique
        for key in (
            "source",
            "target",
            "reader_source",
            "reader_target",
            "replicator",
            "source_app",
            "target_app",
            "publication",
            "subscription",
            "slot",
        )
    }
    bases = {"source": base, "target": target_base or base}
    # Optional second cluster is an explicitly owned fixture, never a provider DSN.
    unique_bases = tuple(dict.fromkeys(bases.values()))
    for cluster in unique_bases:
        with psycopg.connect(cluster, autocommit=True) as root:
            if root.execute("SHOW wal_level").fetchone()[0] != "logical":
                pytest.skip("explicit isolated logical WAL fixture required")
            for key in (
                "reader_source",
                "reader_target",
                "replicator",
                "source_app",
                "target_app",
            ):
                root.execute(
                    sql.SQL(
                        "CREATE ROLE {} {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT {}"
                    ).format(
                        sql.Identifier(names[key]),
                        sql.SQL("NOLOGIN" if key == "target_app" else "LOGIN"),
                        sql.SQL(
                            "REPLICATION" if key == "replicator" else "NOREPLICATION"
                        ),
                    )
                )
                if key == "replicator" and password is not None:
                    root.execute(
                        sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                            sql.Identifier(names[key]), sql.Literal(password)
                        )
                    )
    for side, cluster in bases.items():
        with psycopg.connect(cluster, autocommit=True) as root:
            root.execute(
                sql.SQL("CREATE DATABASE {}").format(sql.Identifier(names[side]))
            )
    dsns = {
        side: make_conninfo(cluster, dbname=names[side])
        for side, cluster in bases.items()
    }
    users = None
    endpoints = []
    definitions = []
    pair = None
    try:
        for side, setup in (("source", source_setup), ("target", target_setup)):
            with psycopg.connect(dsns[side], autocommit=True) as owner:
                value = setup(owner, names[side + "_app"])
                if side == "source":
                    users = value
                owner.execute(
                    "CREATE TABLE public.migration_barriers(boundary_id uuid PRIMARY KEY,plan_digest text NOT NULL,writer_epoch bigint NOT NULL)"
                )
                reader = names["reader_" + side]
                for schema in {table[0] for table in tables}:
                    owner.execute(
                        sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                            sql.Identifier(schema), sql.Identifier(reader)
                        )
                    )
                    owner.execute(
                        sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA {} TO {}").format(
                            sql.Identifier(schema), sql.Identifier(reader)
                        )
                    )
                    owner.execute(
                        sql.SQL(
                            "GRANT SELECT ON ALL SEQUENCES IN SCHEMA {} TO {}"
                        ).format(sql.Identifier(schema), sql.Identifier(reader))
                    )
                owner.execute(
                    sql.SQL("GRANT SELECT ON public.migration_barriers TO {}").format(
                        sql.Identifier(reader)
                    )
                )
                owner.execute(
                    sql.SQL(
                        "GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO {}"
                    ).format(sql.Identifier(reader))
                )
                if side == "target":
                    owner.execute(
                        sql.SQL(
                            "GRANT SELECT(oid,subdbid,subname,subenabled,subpublications) ON pg_catalog.pg_subscription TO {}"
                        ).format(sql.Identifier(reader))
                    )
                identity = owner.execute(
                    "SELECT current_database(),d.oid,c.system_identifier::text FROM pg_catalog.pg_database d CROSS JOIN pg_catalog.pg_control_system() c WHERE d.datname=current_database()"
                ).fetchone()
                endpoints.append(
                    ReplicationEndpoint(
                        ResourceScope("tenant-test", "consultation", side, "postgres"),
                        side + "-reader",
                        *identity,
                        reader,
                        True,
                    )
                )
                definitions.append(
                    {
                        table: table_definition(owner, *table)
                        for table in (*tables, ("public", "migration_barriers"))
                    }
                )
        with psycopg.connect(dsns["source"], autocommit=True) as source:
            for schema in {s for s, _ in (*tables, ("public", "migration_barriers"))}:
                source.execute(
                    sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                        sql.Identifier(schema), sql.Identifier(names["replicator"])
                    )
                )
                source.execute(
                    sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA {} TO {}").format(
                        sql.Identifier(schema), sql.Identifier(names["replicator"])
                    )
                )
            publication_tables = sql.SQL(",").join(
                sql.SQL("{}.{}").format(sql.Identifier(s), sql.Identifier(t))
                for s, t in (*tables, ("public", "migration_barriers"))
            )
            source.execute(
                sql.SQL("CREATE PUBLICATION {} FOR TABLE {}").format(
                    sql.Identifier(names["publication"]), publication_tables
                )
            )
            puboid = source.execute(
                "SELECT oid FROM pg_catalog.pg_publication WHERE pubname=%s",
                (names["publication"],),
            ).fetchone()[0]
            source.execute(
                "SELECT pg_create_logical_replication_slot(%s,%s)",
                (names["slot"], "pgoutput"),
            )
        approved = replication_connection(
            dsns["source"],
            names["replicator"],
            names["subscription"],
            password,
            root_ca,
        )
        with psycopg.connect(dsns["target"], autocommit=True) as target:
            target.execute(
                sql.SQL(
                    "CREATE SUBSCRIPTION {} CONNECTION {} PUBLICATION {} WITH(create_slot=false,slot_name={},copy_data=true)"
                ).format(
                    sql.Identifier(names["subscription"]),
                    sql.Literal(approved),
                    sql.Identifier(names["publication"]),
                    sql.Literal(names["slot"]),
                )
            )
            suboid = target.execute(
                "SELECT oid FROM pg_catalog.pg_subscription WHERE subname=%s",
                (names["subscription"],),
            ).fetchone()[0]

            def ready():
                states = target.execute(
                    "SELECT srsubstate FROM pg_catalog.pg_subscription_rel WHERE srsubid=%s",
                    (suboid,),
                ).fetchall()
                return len(states) == len(tables) + 1 and all(
                    row[0] == "r" for row in states
                )

            wait_for(ready, 20)
        now = datetime.now(UTC)
        registration = ReplicationRegistration(
            *endpoints,
            RevisionSet(*("a" * 64,) * 4),
            names["publication"],
            puboid,
            names["subscription"],
            suboid,
            tuple(
                ReplicatedTable(
                    *table,
                    definitions[0][table]["table_oid"],
                    definitions[1][table]["table_oid"],
                    definitions[0][table]["schema_digest"],
                )
                for table in definitions[0]
            ),
            "public",
            "migration_barriers",
            now - timedelta(seconds=1),
            now + timedelta(minutes=3),
        )
        with psycopg.connect(dsns["target"], autocommit=True) as owner:
            inspector = install_channel_inspector(
                owner,
                reader_role=names["reader_target"],
                subscription_oid=suboid,
                expected_connection_digest=hashlib.sha256(
                    approved.encode()
                ).hexdigest(),
                valid_until=registration.valid_until,
                expected_slot_name=names["slot"],
            )
        registration = replace(registration, inspector=inspector)
        if tls_replication:
            with psycopg.connect(dsns["source"], autocommit=True) as owner:
                publisher = install_publisher_inspector(
                    owner,
                    reader_role=names["reader_source"],
                    slot_name=names["slot"],
                    replicator_role=names["replicator"],
                    application_name=names["subscription"],
                    expected_peer_addresses=("127.0.0.1",),
                    valid_until=registration.valid_until,
                )
            registration = replace(registration, publisher_inspector=publisher)
        pair = LogicalPair(
            dsns,
            names,
            registration,
            users,
            _replication_password=password,
            _root_ca=root_ca,
        )
        yield pair
    finally:
        if pair is not None and pair.reverse_names is not None:
            reverse_names = pair.reverse_names
            with psycopg.connect(dsns["source"], autocommit=True) as original:
                if original.execute(
                    "SELECT 1 FROM pg_subscription WHERE subname=%s",
                    (reverse_names["subscription"],),
                ).fetchone():
                    original.execute(
                        sql.SQL("ALTER SUBSCRIPTION {} DISABLE").format(
                            sql.Identifier(reverse_names["subscription"])
                        )
                    )
                    original.execute(
                        sql.SQL("ALTER SUBSCRIPTION {} SET(slot_name=NONE)").format(
                            sql.Identifier(reverse_names["subscription"])
                        )
                    )
                    original.execute(
                        sql.SQL("DROP SUBSCRIPTION {}").format(
                            sql.Identifier(reverse_names["subscription"])
                        )
                    )
            with psycopg.connect(dsns["target"], autocommit=True) as publisher:
                wait_for(
                    lambda: publisher.execute(
                        "SELECT count(*)=0 FROM pg_replication_slots WHERE slot_name=%s AND active",
                        (reverse_names["slot"],),
                    ).fetchone()[0]
                )
                if publisher.execute(
                    "SELECT 1 FROM pg_replication_slots WHERE slot_name=%s",
                    (reverse_names["slot"],),
                ).fetchone():
                    publisher.execute(
                        "SELECT pg_drop_replication_slot(%s)", (reverse_names["slot"],)
                    )
        with psycopg.connect(dsns["target"], autocommit=True) as target:
            if target.execute(
                "SELECT 1 FROM pg_catalog.pg_subscription WHERE subname=%s",
                (names["subscription"],),
            ).fetchone():
                target.execute(
                    sql.SQL("ALTER SUBSCRIPTION {} DISABLE").format(
                        sql.Identifier(names["subscription"])
                    )
                )
                target.execute(
                    sql.SQL("ALTER SUBSCRIPTION {} SET(slot_name=NONE)").format(
                        sql.Identifier(names["subscription"])
                    )
                )
                target.execute(
                    sql.SQL("DROP SUBSCRIPTION {}").format(
                        sql.Identifier(names["subscription"])
                    )
                )
        with psycopg.connect(dsns["source"], autocommit=True) as source:
            wait_for(
                lambda: source.execute(
                    "SELECT count(*)=0 FROM pg_catalog.pg_replication_slots WHERE database=current_database() AND active"
                ).fetchone()[0]
            )
            for (slot,) in source.execute(
                "SELECT slot_name FROM pg_catalog.pg_replication_slots WHERE database=current_database()"
            ).fetchall():
                source.execute("SELECT pg_drop_replication_slot(%s)", (slot,))
        for side in ("target", "source"):
            with psycopg.connect(bases[side], autocommit=True) as root:
                root.execute(
                    sql.SQL("DROP DATABASE {} WITH(FORCE)").format(
                        sql.Identifier(names[side])
                    )
                )
        for cluster in unique_bases:
            with psycopg.connect(cluster, autocommit=True) as root:
                for key in (
                    "reader_source",
                    "reader_target",
                    "replicator",
                    "source_app",
                    "target_app",
                ):
                    root.execute(
                        sql.SQL("DROP ROLE {}").format(sql.Identifier(names[key]))
                    )
