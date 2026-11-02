"""Opt-in real non-root workload image + native PG verify-full TLS qualification.

All inputs are synthetic. No Docker socket or cloud credentials enter the app.
Only this fixture's two named volumes and containers are created/removed.
"""

from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time
from uuid import uuid4

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
import pytest

from examples.consultation.operator import prepare

pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(
        not os.environ.get("SOVA_TEST_WORKLOAD_IMAGE"),
        reason="explicit image + private TLS PostgreSQL fixture required",
    ),
]


def test_actual_nonroot_image_database_tls_and_restart_persistence(postgres_database):
    requests = pytest.importorskip("requests")
    dsn, _ = postgres_database
    ca = Path(os.environ["SOVA_TEST_POSTGRES_TLS_ROOT"]) / "ca.pem"
    port = conninfo_to_dict(dsn)["port"]
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        appport = listener.getsockname()[1]
    origin = f"http://127.0.0.1:{appport}"
    uid = uuid4().hex[:12]
    name = "sova-chat-image-" + uid
    secrets_volume = name + "-secrets"
    objects_volume = name + "-objects"
    role = "chat_image_" + uid
    password = secrets.token_urlsafe(32)
    image = os.environ["SOVA_TEST_WORKLOAD_IMAGE"]

    def docker(*args, **kwargs):
        requested_check = kwargs.pop("check", True)
        result = subprocess.run(
            ["docker", *args],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            **kwargs,
        )
        if result.returncode and requested_check:
            raise RuntimeError(
                "Own workload container command failed: " + result.stderr[-2000:]
            )
        return result

    session = requests.Session()
    session.trust_env = False
    try:
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION NOINHERIT PASSWORD {}"
                ).format(sql.Identifier(role), sql.Literal(password))
            )
            users = prepare(
                admin,
                schema="consultation",
                app_role=role,
                valid_until=datetime.now(UTC) + timedelta(minutes=15),
            )
        for volume in (secrets_volume, objects_volume):
            docker(
                "volume",
                "create",
                "--label",
                "io.sova.fixture=consultation-image",
                volume,
            )
        secret_dsn = make_conninfo(
            host="host.docker.internal",
            port=port,
            dbname=conninfo_to_dict(dsn)["dbname"],
            user=role,
            password=password,
            sslmode="verify-full",
            sslrootcert="/run/secrets/ca.pem",
        )
        initialize = """import json,os,pathlib,sys
value=json.load(sys.stdin)
root=pathlib.Path('/secrets')
for name,content in value.items():
 p=root/name;p.write_text(content);p.chmod(0o400);os.chown(p,10001,10001)
os.chmod('/objects',0o700);os.chown('/objects',10001,10001)
"""
        docker(
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CHOWN",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "0:0",
            "--mount",
            f"type=volume,src={secrets_volume},dst=/secrets",
            "--mount",
            f"type=volume,src={objects_volume},dst=/objects",
            "-i",
            "--entrypoint",
            "python",
            image,
            "-c",
            initialize,
            input=json.dumps({"database.dsn": secret_dsn, "ca.pem": ca.read_text()}),
        )
        run = [
            "run",
            "-d",
            "--name",
            name,
            "--label",
            "io.sova.fixture=consultation-image",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "64",
            "--memory",
            "256m",
            "--cpus",
            "1",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--mount",
            f"type=volume,src={secrets_volume},dst=/run/secrets,readonly",
            "--mount",
            f"type=volume,src={objects_volume},dst=/data/objects",
            "--publish",
            f"127.0.0.1:{appport}:8080",
            "--env",
            "DATABASE_URL_FILE=/run/secrets/database.dsn",
            "--env",
            "CONSULTATION_ENVIRONMENT=source-container",
            "--env",
            f"CONSULTATION_ORIGIN={origin}",
            "--env",
            "CONSULTATION_REVISION=" + "a" * 64,
            image,
        ]

        def start():
            docker(*run)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    result = session.get(origin + "/health", timeout=2)
                    if result.status_code == 200:
                        return result.json()
                except requests.ConnectionError:
                    pass
                time.sleep(0.1)
            pytest.fail(
                "Own consultation image did not become healthy: "
                + docker("logs", name, check=False).stderr[-3000:]
            )

        health = start()
        assert health["environment"] == "source-container"

        def replace_secret(filename, text):
            script = "import json,pathlib,sys; p=pathlib.Path('/secrets')/sys.argv[1]; p.chmod(0o600); p.write_text(json.load(sys.stdin)); p.chmod(0o400)"
            docker(
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--user",
                "10001:10001",
                "--mount",
                f"type=volume,src={secrets_volume},dst=/secrets",
                "-i",
                "--entrypoint",
                "python",
                image,
                "-c",
                script,
                filename,
                input=json.dumps(text),
            )

        # A valid but unrelated trust root must fail; verification is not disabled.
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "untrusted-private-fixture")]
        )
        untrusted = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
            .not_valid_after(datetime.now(UTC) + timedelta(minutes=10))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM)
            .decode()
        )
        replace_secret("ca.pem", untrusted)
        assert session.get(origin + "/health", timeout=3).status_code == 503
        replace_secret("ca.pem", ca.read_text())
        assert session.get(origin + "/health", timeout=3).status_code == 200
        replace_secret(
            "database.dsn",
            make_conninfo(secret_dsn, password="not-the-fixture-password"),
        )
        assert session.get(origin + "/health", timeout=3).status_code == 503
        replace_secret("database.dsn", secret_dsn)
        assert session.get(origin + "/health", timeout=3).status_code == 200
        expected_image = json.loads(docker("image", "inspect", image).stdout)[0]["Id"]
        info = json.loads(docker("inspect", name).stdout)[0]
        assert (
            info["Config"]["User"] == "10001:10001"
            and info["HostConfig"]["ReadonlyRootfs"]
        )
        assert all(
            "docker.sock" not in mount["Destination"] for mount in info["Mounts"]
        )
        session.headers["Origin"] = origin
        login = session.post(
            origin + "/api/session", json={"invite": users[0]["invite"]}, timeout=3
        )
        assert login.status_code == 200
        session.headers["X-Consultation-CSRF"] = login.json()["csrf"]
        room = users[0]["room_id"]
        request_id = str(uuid4())
        message = {
            "client_request_id": request_id,
            "content": "container restart synthetic message",
        }
        sent = session.post(
            origin + f"/api/rooms/{room}/messages", json=message, timeout=3
        )
        assert sent.status_code == 200
        attachment = str(uuid4())
        content = b"synthetic private attachment"
        saved = session.put(
            origin + f"/api/rooms/{room}/attachments/{attachment}",
            data=content,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Filename": "test.txt",
            },
            timeout=3,
        )
        assert saved.status_code == 200
        docker(
            "exec",
            name,
            "python",
            "-c",
            "import importlib.util,os,pathlib,shutil; assert os.geteuid()==10001; assert importlib.util.find_spec('consultation.operator') is None; assert importlib.util.find_spec('consultation.manage') is None; assert not pathlib.Path('/app/consultation/schema.sql').exists(); assert shutil.which('docker') is None",
        )
        docker("stop", "--time", "5", name)
        docker("rm", name)
        start()
        assert json.loads(docker("inspect", name).stdout)[0]["Image"] == expected_image
        rows = session.get(origin + f"/api/rooms/{room}/messages", timeout=3).json()
        assert len(rows) == 1 and rows[0]["id"] == sent.json()["id"]
        assert (
            session.post(
                origin + f"/api/rooms/{room}/messages", json=message, timeout=3
            ).json()
            == sent.json()
        )
        response = session.get(
            origin + f"/api/rooms/{room}/attachments/{attachment}", timeout=3
        )
        assert (
            response.status_code == 200
            and hashlib.sha256(response.content).digest()
            == hashlib.sha256(content).digest()
        )
    finally:
        session.close()
        docker("rm", "-f", name, check=False)
        for volume in (secrets_volume, objects_volume):
            docker("volume", "rm", volume, check=False)
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute("DROP SCHEMA IF EXISTS consultation CASCADE")
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            admin.execute(
                sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role))
            )
