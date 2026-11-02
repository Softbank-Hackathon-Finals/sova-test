"""Owner-only synthetic fixture management. Excluded from the service image.

No credentials or invite codes are printed. This is not a Sova production
approval/executor and does not discover or fence arbitrary external writers.
"""

import argparse
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import re
import sys

import psycopg
from psycopg import sql

from .operator import prepare, invite, set_writes
from .private_files import private_text


def name(value):
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value):
        raise ValueError("Bounded SQL identifier required")
    return value


def private_output(path):
    path = Path(path).absolute()
    parent = path.parent.stat()
    if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
        raise ValueError("Owner-controlled output directory required")
    return path, os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Operator-only synthetic consultation fixture management"
    )
    parser.add_argument(
        "command", choices=("prepare", "issue-invites", "pause", "resume")
    )
    parser.add_argument("--owner-dsn-file", required=True)
    parser.add_argument("--schema", default="consultation")
    parser.add_argument("--runtime-role")
    parser.add_argument("--private-output")
    parser.add_argument("--invite-minutes", type=int, default=30)
    args = parser.parse_args(argv)
    output = None
    try:
        schema = name(args.schema)
        if not 1 <= args.invite_minutes <= 120:
            raise ValueError("Bounded invite validity required")
        if args.command in {"prepare", "issue-invites"}:
            if not args.private_output:
                raise ValueError("Private output file required")
            output, fd = private_output(args.private_output)
        else:
            fd = None
        try:
            with psycopg.connect(
                private_text(args.owner_dsn_file),
                connect_timeout=5,
                options="-c statement_timeout=5000 -c lock_timeout=1000",
            ) as owner:
                if args.command == "prepare":
                    if not args.runtime_role:
                        raise ValueError("Precreated app runtime role required")
                    role = name(args.runtime_role)
                    privileges = owner.execute(
                        "SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=%s",
                        (role,),
                    ).fetchone()
                    if privileges is None or any(privileges):
                        raise ValueError("Precreated nonprivileged app role required")
                    users = prepare(
                        owner,
                        schema=schema,
                        app_role=role,
                        valid_until=datetime.now(UTC)
                        + timedelta(minutes=args.invite_minutes),
                    )
                elif args.command == "issue-invites":
                    rows = owner.execute(
                        sql.SQL(
                            "SELECT user_id::text,display_name,role FROM {}.users WHERE NOT disabled ORDER BY user_id LIMIT 33"
                        ).format(sql.Identifier(schema))
                    ).fetchall()
                    if not 1 <= len(rows) <= 32:
                        raise ValueError("Small synthetic fixture users required")
                    owner.execute(
                        sql.SQL(
                            "UPDATE {}.invitations SET expires_at=clock_timestamp() WHERE consumed_at IS NULL"
                        ).format(sql.Identifier(schema))
                    )
                    users = [
                        dict(
                            user_id=user,
                            display_name=display,
                            role=role,
                            invite=invite(
                                owner,
                                schema,
                                user,
                                datetime.now(UTC)
                                + timedelta(minutes=args.invite_minutes),
                            ),
                        )
                        for user, display, role in rows
                    ]
                else:
                    epoch = set_writes(
                        owner, schema=schema, enabled=args.command == "resume"
                    )
                if fd is not None:
                    with os.fdopen(fd, "w", encoding="utf-8") as stream:
                        fd = None
                        json.dump(
                            {
                                "scope": "synthetic-reference-app-only",
                                "schema": schema,
                                "users": users,
                            },
                            stream,
                            ensure_ascii=False,
                            indent=2,
                        )
                        stream.flush()
                        os.fsync(stream.fileno())
            print(
                json.dumps(
                    {
                        "status": "completed",
                        "command": args.command,
                        "schema": schema,
                        **(
                            {"private_output": str(output)}
                            if output
                            else {
                                "writer_epoch": epoch,
                                "scope": "instrumented app only; external writer fencing unverified",
                            }
                        ),
                    },
                    ensure_ascii=False,
                )
            )
            return 0
        finally:
            if fd is not None:
                os.close(fd)
    except (OSError, ValueError, psycopg.Error) as exc:
        if output is not None:
            output.unlink(missing_ok=True)
        # Never echo a connection string, invitation, SQL or provider exception.
        print(
            "Reference fixture command failed: " + type(exc).__name__, file=sys.stderr
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
