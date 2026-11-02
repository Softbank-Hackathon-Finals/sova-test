"""Repeatable owner-local security demo. No AWS calls or existing cluster changes.

Each start creates an isolated k3s-in-Docker and private Unix-socket PostgreSQL.
The supervisor cleans up its own processes/container at the deadline. Records
remain private so a new demonstration never erases an incident or approval.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
from dependency_bridge import DependencyBridge

PROJECT = Path(__file__).resolve().parents[1]
K3S_IMAGE = "rancher/k3s@sha256:ec9868c6a38d4e8c1869832fb5fd1eb8473c39794a0b44d2b952e7ba911951bc"
LABEL = "io.sova.security-demo"


def write_private(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def checked(command, *, timeout=30, input=None):
    result = subprocess.run(
        command, input=input, capture_output=True, text=True, timeout=timeout
    )
    if result.returncode:
        raise RuntimeError("Command failed: " + Path(command[0]).name)
    return result.stdout


def owned_container(record, inspection):
    """Names alone are not authority to remove a container."""
    return (
        inspection.get("Id") == record.get("container_id")
        and inspection.get("Name") == "/" + record.get("name", "")
        and inspection.get("Config", {}).get("Labels", {}).get(LABEL)
        == record.get("run_id")
    )


class Demo:
    def __init__(self, root, settings):
        self.root = root
        self.settings = settings
        self.children = []
        self.cluster = None
        self.database_started = False
        self.stopped = False

    def log(self, stage):
        write_private(
            self.root / "progress.json",
            {"stage": stage, "at": datetime.now(UTC).isoformat()},
        )
        print(stage, flush=True)

    def spawn(self, command, name):
        with (self.root / (name + ".log")).open("ab") as stream:
            child = subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=stream, stderr=stream
            )
        self.children.append(child)
        return child

    def kube(self, *args, timeout=30):
        return checked(
            [
                "kubectl",
                "--kubeconfig",
                str(self.root / "admin-kubeconfig.json"),
                "--request-timeout=10s",
                *args,
            ],
            timeout=timeout,
        )

    def setup_database(self):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo

        binary = Path(self.settings["pg_bin"])
        data = self.root / "pgdata"
        # macOS Unix socket paths are short; the data and evidence remain in root.
        import tempfile

        sock = Path(tempfile.mkdtemp(prefix="sova-demo-sock-", dir="/private/tmp"))
        sock.chmod(0o700)
        write_private(self.root / "socket.json", {"path": str(sock)})
        checked(
            [
                str(binary / "initdb"),
                "-D",
                str(data),
                "-L",
                self.settings["pg_share"],
                "-A",
                "trust",
                "-U",
                "sova_console_admin",
                "--no-locale",
                "--encoding=UTF8",
            ],
            timeout=40,
        )
        # pg_ctl may time out after the server starts; still attempt shutdown.
        self.database_started = True
        checked(
            [
                str(binary / "pg_ctl"),
                "-D",
                str(data),
                "-l",
                str(self.root / "postgres.log"),
                "-o",
                f"-k {sock} -p 54331 -c listen_addresses=''",
                "-w",
                "start",
            ]
        )
        admin = make_conninfo(
            host=str(sock), port=54331, dbname="postgres", user="sova_console_admin"
        )
        with psycopg.connect(admin, autocommit=True) as conn:
            conn.execute("CREATE DATABASE sova_console")
        admin = make_conninfo(admin, dbname="sova_console")
        with psycopg.connect(admin, autocommit=True) as conn:
            for name in (
                "postgres_lifecycle_v1",
                "postgres_lifecycle_v2",
                "postgres_operations_v1",
                "postgres_execution_v1",
                "postgres_governance_v1",
                "postgres_governance_v2",
                "postgres_security_observations_v1",
                "postgres_signed_evidence_v1",
                "postgres_protection_parity_v1",
                "postgres_verifier_registry_v1",
            ):
                conn.execute(
                    (PROJECT / "src/sova/adapters/sql" / (name + ".sql")).read_text()
                )
            for role, write in (
                ("sova_security_recorder", True),
                ("sova_security_viewer", False),
            ):
                conn.execute(
                    sql.SQL(
                        "CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT"
                    ).format(sql.Identifier(role))
                )
                conn.execute(
                    sql.SQL("GRANT USAGE ON SCHEMA sova_control TO {}").format(
                        sql.Identifier(role)
                    )
                )
                for table in (
                    "security_snapshots",
                    "security_event_log",
                    "security_hold_events",
                ):
                    conn.execute(
                        sql.SQL("GRANT {} ON sova_control.{} TO {}").format(
                            sql.SQL("SELECT,INSERT" if write else "SELECT"),
                            sql.Identifier(table),
                            sql.Identifier(role),
                        )
                    )
                if write:
                    conn.execute(
                        sql.SQL(
                            "GRANT USAGE ON SEQUENCE sova_control.security_event_log_sequence_seq TO {}"
                        ).format(sql.Identifier(role))
                    )
        write_private(
            self.root / "control-db.json",
            {
                "data": str(data),
                "socket": str(sock),
                "pg_ctl": str(binary / "pg_ctl"),
                "admin_dsn": admin,
                "recorder_dsn": make_conninfo(admin, user="sova_security_recorder"),
                "viewer_dsn": make_conninfo(admin, user="sova_security_viewer"),
                "local_only": True,
            },
        )

    def setup(self):
        self.log("준비: 전용 로컬 k3s")
        run_id = self.settings["run_id"]
        name = "sova-team-demo-" + run_id
        # Pulling a different tag is deliberately not a silent fallback.
        checked(["docker", "image", "inspect", K3S_IMAGE])
        checked(["docker", "image", "inspect", "python:3.12-slim"])
        container = checked(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--privileged",
                "--name",
                name,
                "--label",
                LABEL + "=" + run_id,
                "--cpus",
                "2",
                "--memory",
                "2g",
                "--pids-limit",
                "1024",
                "--tmpfs",
                "/run",
                "-p",
                "127.0.0.1::6443",
                K3S_IMAGE,
                "server",
                "--disable",
                "traefik",
                "--disable",
                "servicelb",
                "--disable",
                "local-storage",
                "--disable",
                "metrics-server",
                "--tls-san",
                "localhost",
                "--node-name",
                "sova-security-node",
                "--write-kubeconfig-mode",
                "600",
            ],
            timeout=90,
        ).strip()
        # Save ownership before any further call that might fail.
        self.cluster = {
            "name": name,
            "container_id": container,
            "run_id": run_id,
            "image": K3S_IMAGE,
        }
        write_private(self.root / "cluster.json", self.cluster)
        inspection = json.loads(checked(["docker", "inspect", container]))[0]
        port = next(
            p["HostPort"]
            for p in inspection["NetworkSettings"]["Ports"]["6443/tcp"]
            if p["HostIp"] == "127.0.0.1"
        )
        self.cluster["endpoint"] = "https://localhost:" + port
        write_private(self.root / "cluster.json", self.cluster)
        for _ in range(60):
            if self.stopped:
                raise RuntimeError("Setup cancelled")
            try:
                config = json.loads(
                    checked(
                        [
                            "docker",
                            "exec",
                            container,
                            "kubectl",
                            "config",
                            "view",
                            "--raw",
                            "-o",
                            "json",
                        ]
                    )
                )
                config["clusters"][0]["cluster"]["server"] = self.cluster["endpoint"]
                write_private(self.root / "admin-kubeconfig.json", config)
                self.kube(
                    "wait",
                    "--for=condition=Ready",
                    "node/sova-security-node",
                    "--timeout=5s",
                    timeout=10,
                )
                break
            except (
                RuntimeError,
                KeyError,
                IndexError,
                TypeError,
                subprocess.TimeoutExpired,
            ):
                time.sleep(1)
        else:
            raise RuntimeError("Cluster readiness deadline")
        self.log("준비: 격리된 PostgreSQL·시험앱·관측 권한")
        self.setup_database()
        for step in (
            "prepare_workload",
            "prepare_readers",
            "freeze_clean_target",
            "prepare_response_runtime",
        ):
            result = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT / "demo/demo_setup" / (step + ".py")),
                    str(self.root),
                ],
                cwd=PROJECT,
                env={**os.environ, "PYTHONPATH": str(PROJECT / "src")},
                capture_output=True,
                text=True,
                timeout=240,
            )
            (self.root / (step + ".log")).write_text(result.stdout + result.stderr)
            if result.returncode:
                raise RuntimeError("Setup failed: " + step + "; inspect private log")
        forward = json.loads((self.root / "probe-forward.json").read_text())
        self.forward_pid = forward["pid"]
        if self.settings.get("dependency_port") is not None:
            self.launch_dependency()
        self.launch_console()

    def launch_dependency(self):
        self.log("준비: 프로세스 의존성·장애 주입 실험")
        self.dependency = self.spawn(
            [
                sys.executable,
                str(PROJECT / "demo/graph_demo.py"),
                "--port",
                str(self.settings["dependency_port"]),
                "--until",
                json.loads((self.root / "session.json").read_text())["deadline"],
                "--state-root",
                str(self.root / "dependency"),
            ],
            "dependency",
        )
        bridge = DependencyBridge(self.settings["dependency_port"])
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.dependency.poll() is not None:
                raise RuntimeError("Dependency Lab stopped; inspect private log")
            try:
                state = bridge.state()
                if not state["nodes"] or not all(
                    n["observation"]["available"] and not n["stale"]
                    for n in state["nodes"]
                ):
                    raise RuntimeError("Dependency processes not ready")
                write_private(
                    self.root / "dependency-ready.json",
                    {
                        "application_id": state["application"]["id"],
                        "node_count": len(state["nodes"]),
                        "port": self.settings["dependency_port"],
                    },
                )
                return
            except (RuntimeError, ValueError):
                time.sleep(0.5)
        raise RuntimeError("Dependency readiness deadline")

    def launch_console(self):
        extra = (
            [
                "--no-migration",
                "--dependency-port",
                str(self.settings["dependency_port"]),
            ]
            if self.settings.get("dependency_port") is not None
            else ["--security-only"]
        )
        if self.settings.get("migration_port") is not None:
            extra = [
                "--migration-port",
                str(self.settings["migration_port"]),
                "--migration-token-file",
                self.settings["migration_token_file"],
            ]
            if self.settings.get("dependency_port") is not None:
                extra += ["--dependency-port", str(self.settings["dependency_port"])]
        self.console = self.spawn(
            [
                sys.executable,
                str(PROJECT / "demo/security_console.py"),
                "--session-root",
                str(self.root),
                "--port",
                str(self.settings["port"]),
                "--ui-root",
                str(PROJECT / "console/dist"),
                *extra,
            ],
            "console",
        )
        for _ in range(100):
            if (self.root / "operator-access.json").exists() and (
                self.root / "console-server.json"
            ).exists():
                self.log("대기: 운영자 로그인·통합 시연 준비 완료")
                return
            if self.console.poll() is not None:
                raise RuntimeError("Console failed; inspect private console log")
            time.sleep(0.2)
        raise RuntimeError("Console startup deadline")

    def renew_login(self):
        """Owner-only console restart; never replays a recorded external effect."""
        self.console.terminate()
        self.console.wait(timeout=55)
        shutdown = json.loads((self.root / "console-shutdown.json").read_text())
        if not all(
            shutdown.get("drain", {}).get(key) is True
            for key in ("collector_stopped", "action_drained")
        ):
            raise RuntimeError("Console did not drain; login renewal requires review")
        (self.root / "console-server.json").unlink(missing_ok=True)
        self.launch_console()

    def refresh_tokens(self):
        for env in ("blue", "green"):
            token = self.kube(
                "-n",
                "sova-live-observer",
                "create",
                "token",
                "sova-reader-" + env,
                "--duration=15m",
            ).strip()
            path = self.root / (env + "-token")
            temp = path.with_suffix(".new")
            fd = os.open(
                temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600
            )
            with os.fdopen(fd, "w") as stream:
                stream.write(token)
            os.replace(temp, path)

    def cleanup(self):
        errors = []
        for child in reversed(self.children):
            try:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=35)
            except subprocess.TimeoutExpired:
                try:
                    child.kill()
                    child.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    errors.append("owned_child_stop_unverified")
            except OSError:
                errors.append("owned_child_stop_unverified")
        # Cleanup of one resource must not prevent attempts on the others.
        try:
            self.stop_probe()
        except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired):
            errors.append("owned_probe_stop_unverified")
        try:
            self.stop_cluster()
        except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired):
            errors.append("owned_cluster_stop_unverified")
        try:
            self.stop_database()
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            errors.append("owned_database_stop_unverified")
        write_private(
            self.root / "cleanup.json",
            {
                "at": datetime.now(UTC).isoformat(),
                "errors": errors,
                "records_preserved": True,
            },
        )
        self.log("종료: 시험 자원 정리" if not errors else "종료: 정리 결과 확인 필요")

    def stop_probe(self):
        forward = self.root / "probe-forward.json"
        if forward.exists():
            data = json.loads(forward.read_text())
            command = (
                checked(["ps", "-p", str(data["pid"]), "-o", "command="])
                if process_alive(data["pid"])
                else ""
            )
            if (
                "port-forward" in command
                and str(self.root / "admin-kubeconfig.json") in command
            ):
                os.kill(data["pid"], signal.SIGTERM)

    def stop_cluster(self):
        if self.cluster:
            result = subprocess.run(
                ["docker", "inspect", self.cluster["container_id"]],
                capture_output=True,
                text=True,
                timeout=20,
            )
            if result.returncode == 0:
                inspection = json.loads(result.stdout)[0]
                if owned_container(self.cluster, inspection):
                    stop = subprocess.run(
                        [
                            "docker",
                            "stop",
                            "-t",
                            "10",
                            self.cluster["container_id"],
                        ],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    write_private(
                        self.root / "cluster-stop-request.json",
                        {"returncode": stop.returncode},
                    )
                else:
                    raise RuntimeError("Cluster ownership mismatch")
                # --rm containers must actually disappear; daemon errors are unknown.
                deadline = time.monotonic() + 10
                while True:
                    absent = checked(
                        [
                            "docker",
                            "ps",
                            "-a",
                            "--no-trunc",
                            "--filter",
                            "id=" + self.cluster["container_id"],
                            "--format",
                            "{{.ID}}",
                        ],
                        timeout=5,
                    )
                    if self.cluster["container_id"] not in absent.splitlines():
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Owned cluster still exists")
                    time.sleep(0.25)
            elif (
                "no such object" not in result.stderr.lower()
                and "no such container" not in result.stderr.lower()
            ):
                raise RuntimeError("Cannot confirm owned cluster state")

    def stop_database(self):
        if self.database_started:
            result = subprocess.run(
                [
                    str(Path(self.settings["pg_bin"]) / "pg_ctl"),
                    "-D",
                    str(self.root / "pgdata"),
                    "-m",
                    "fast",
                    "-w",
                    "stop",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode:
                raise RuntimeError("Owned database stop failed")


def process_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=("start", "supervise", "status", "stop", "login")
    )
    parser.add_argument("--root", type=Path)
    parser.add_argument("--pg-bin", type=Path)
    parser.add_argument("--pg-share", type=Path)
    parser.add_argument("--minutes", type=int, default=110)
    parser.add_argument(
        "--until",
        help="Explicit timezone-aware runtime deadline, at most 12 hours ahead",
    )
    parser.add_argument("--port", type=int, default=8792)
    parser.add_argument("--dependency-port", type=int, default=8791)
    parser.add_argument("--migration-port", type=int)
    parser.add_argument("--migration-token-file", type=Path)
    parser.add_argument(
        "--security-only",
        action="store_true",
        help="Skip the separate process experiment",
    )
    parser.add_argument(
        "--open", action="store_true", help="Open owner-only login in the local browser"
    )
    parser.add_argument(
        "--renew",
        action="store_true",
        help="Owner-only console restart for a fresh one-time login; records preserved",
    )
    args = parser.parse_args()
    if args.action == "start":
        if args.migration_port is not None and (
            args.migration_port in {args.port, args.dependency_port}
            or not 1024 <= args.migration_port <= 65535
            or not args.migration_token_file
            or args.security_only
        ):
            parser.error(
                "migration requires a distinct port, private token file, and combined mode"
            )
        if not 5 <= args.minutes <= 115 or not 1024 <= args.port <= 65535:
            parser.error("minutes must be 5..115; port must be 1024..65535")
        try:
            deadline = (
                datetime.fromisoformat(args.until)
                if args.until
                else datetime.now(UTC) + timedelta(minutes=args.minutes)
            )
            if deadline.tzinfo is None or not timedelta(
                minutes=5
            ) <= deadline - datetime.now(UTC) <= timedelta(hours=12):
                raise ValueError()
        except ValueError:
            parser.error(
                "--until must have a timezone and be 5 minutes to 12 hours ahead"
            )
        if not args.pg_bin or not args.pg_share:
            parser.error("explicit --pg-bin and --pg-share required")
        for command in ("docker", "kubectl"):
            if not shutil.which(command):
                parser.error(command + " is required")
        for binary in ("initdb", "pg_ctl"):
            if not (args.pg_bin / binary).is_file():
                parser.error("PostgreSQL executable missing: " + binary)
        if " 17." not in checked([str(args.pg_bin / "pg_ctl"), "--version"]):
            parser.error("this demo profile requires PostgreSQL 17")
        if not (PROJECT / "console/dist/index.html").is_file():
            parser.error("Build console first: cd console && npm run build")
        with socket.socket() as check:
            check.bind(("127.0.0.1", args.port))
        if not args.security_only:
            if not 1024 <= args.dependency_port <= 65535 or args.dependency_port in {
                args.port,
                8790,
            }:
                parser.error("dependency port must be distinct and between 1024..65535")
            with socket.socket() as check:
                check.bind(("127.0.0.1", args.dependency_port))
        run_id = secrets.token_hex(5)
        root = args.root or PROJECT / ".local-notes/team-demo" / run_id
        root = root.resolve()
        root.mkdir(parents=True, mode=0o700, exist_ok=False)
        root.chmod(0o700)
        settings = {
            "run_id": run_id,
            "port": args.port,
            "dependency_port": None if args.security_only else args.dependency_port,
            "migration_port": args.migration_port,
            "migration_token_file": str(args.migration_token_file.resolve())
            if args.migration_token_file
            else None,
            "pg_bin": str(args.pg_bin.resolve()),
            "pg_share": str(args.pg_share.resolve()),
        }
        write_private(root / "settings.json", settings)
        write_private(
            root / "session.json",
            {
                "deadline": deadline.isoformat(),
                "scope": "dedicated local k3s; stateless security-response demonstration",
            },
        )
        with (root / "supervisor.log").open("wb") as log:
            child = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "supervise",
                    "--root",
                    str(root),
                ],
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
                start_new_session=True,
            )
        write_private(root / "supervisor.json", {"pid": child.pid})
        print("Private run directory: " + str(root))
        print("Progress: security_demo.py status --root " + str(root))
        return
    if not args.root:
        parser.error("--root is required")
    root = args.root.resolve()
    if (
        root.is_symlink()
        or root.stat().st_uid != os.geteuid()
        or root.stat().st_mode & 0o077
    ):
        parser.error("owner-private run directory required")
    if args.action == "status":
        for name in ("progress.json", "console-server.json", "cleanup.json"):
            if (root / name).exists():
                print(name + ": " + (root / name).read_text().strip())
        return
    if args.action == "stop":
        (root / "finish-now").touch(mode=0o600)
        print("Stop requested. Check cleanup.json; previous records are preserved.")
        return
    if args.action == "login":
        if args.renew:
            before = (
                (root / "operator-access.json").read_text()
                if (root / "operator-access.json").exists()
                else ""
            )
            (root / "renew-login").touch(mode=0o600)
            for _ in range(300):
                path = root / "operator-access.json"
                if (
                    not (root / "renew-login").exists()
                    and path.exists()
                    and path.read_text() != before
                ):
                    break
                if (root / "cleanup.json").exists():
                    parser.error("demo already stopped; start a fresh run")
                time.sleep(0.2)
            else:
                parser.error("login renewal not confirmed; inspect supervisor state")
        data = json.loads((root / "operator-access.json").read_text())
        if datetime.now(UTC) >= datetime.fromisoformat(data["expires_at"]):
            parser.error(
                "one-time login expired; restart the console with the registered session"
            )
        if args.open:
            checked(["open", data["url"]])
            print("Opened owner login; token not printed.")
        else:
            print("Owner-only login is stored in " + str(root / "operator-access.json"))
        return
    os.umask(0o077)
    demo = Demo(root, json.loads((root / "settings.json").read_text()))
    signal.signal(signal.SIGTERM, lambda *_: setattr(demo, "stopped", True))
    signal.signal(signal.SIGINT, lambda *_: setattr(demo, "stopped", True))
    deadline = datetime.fromisoformat(
        json.loads((root / "session.json").read_text())["deadline"]
    )
    try:
        if sys.platform == "darwin":
            demo.spawn(
                [
                    "/usr/bin/caffeinate",
                    "-di",
                    "-t",
                    str(max(1, int((deadline - datetime.now(UTC)).total_seconds()))),
                ],
                "awake",
            )
        demo.setup()
        refreshed = time.monotonic()
        while (
            not demo.stopped
            and datetime.now(UTC) < deadline
            and not (root / "finish-now").exists()
        ):
            if demo.console.poll() is not None:
                break
            if (root / "renew-login").exists():
                demo.renew_login()
                (root / "renew-login").unlink()
            if time.monotonic() - refreshed >= 300:
                demo.refresh_tokens()
                refreshed = time.monotonic()
            time.sleep(1)
    except Exception as exc:
        write_private(
            root / "failure.json",
            {"type": type(exc).__name__, "message": str(exc)[:200]},
        )
        raise
    finally:
        demo.cleanup()


if __name__ == "__main__":
    main()
