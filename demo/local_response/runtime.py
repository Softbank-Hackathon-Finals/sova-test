"""Finite local response runner with a durable command/effect journal.

Plans bind the cluster, namespace identities, pod UIDs and exact command revision.
Unknown effects are held on restart. HTTP retries cannot rerun a mutation.
"""

import json
from pathlib import Path
import secrets
import sqlite3
import threading
import time

from .evidence import ResponseEvidence, sha
from .security import SecurityGate
from .kube import Kube, Unconfirmed
from .manifests import NAMESPACES, PROFILE, configure, placement
from .provision import private_json

from sova_security.contracts.commands import ContractError

from .contracts import SCENARIOS, SIGNALS, now, digest, require
from .operations import ResponseOperations
from .observation import RuntimeObservation


class Runtime(ResponseOperations, RuntimeObservation):
    def __init__(self, root, kube=None):
        self.root = Path(root)
        self.settings = json.loads((self.root / "settings.private.json").read_text())
        configure(self.settings.get("topology", "local"))
        self.kube = kube or Kube.from_settings(self.settings)
        self.security = SecurityGate(self)
        self.support_view = None
        self.support_checked = 0.0
        self.evidence = ResponseEvidence(
            self.root, tenant=PROFILE["owner"], namespace=NAMESPACES["source"]
        )
        self.lock = threading.RLock()
        self.observation = None
        self.busy = False
        self.db = sqlite3.connect(
            self.root / "responses.sqlite", check_same_thread=False
        )
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(
            "CREATE TABLE IF NOT EXISTS state(id integer PRIMARY KEY CHECK(id=1),body text NOT NULL); CREATE TABLE IF NOT EXISTS effects(id text PRIMARY KEY,request_hash text NOT NULL,status text NOT NULL,body text NOT NULL); CREATE TABLE IF NOT EXISTS journal(seq integer PRIMARY KEY AUTOINCREMENT,at text NOT NULL,kind text NOT NULL,body text NOT NULL);"
        )
        row = self.db.execute("SELECT body FROM state WHERE id=1").fetchone()
        self.state = json.loads(row[0]) if row else self.empty()
        unfinished = self.db.execute(
            "SELECT id FROM effects WHERE status='started'"
        ).fetchall()
        if unfinished:
            self.state["phase"] = "held"
            self.event(
                "held",
                "이전 실행 결과가 불명확합니다. 실제 상태 확인 전 자동 재실행하지 않습니다.",
            )
            self.db.execute(
                "UPDATE effects SET status='unknown' WHERE status='started'"
            )
        self.save()

    def empty(self, scenario="segment", revision=0):
        return {
            "scenario": scenario,
            "phase": "normal",
            "recovery": None,
            "approved": False,
            "preapproved": False,
            "outcome": "unknown",
            "source": "local-rke2",
            "revision": revision,
            "history": [],
            "checks": [],
            "plan": None,
            "evidence": {},
            "run_id": secrets.token_hex(8),
        }

    def event(self, phase, message):
        event = {
            "phase": phase,
            "message": message,
            "provenance": "local-rke2",
            "at": now(),
        }
        self.state["history"].append(event)
        self.db.execute(
            "INSERT INTO journal(at,kind,body) VALUES(?,?,?)",
            (event["at"], "event", json.dumps(event, ensure_ascii=False)),
        )

    def save(self):
        self.db.execute(
            "INSERT INTO state VALUES(1,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body",
            (json.dumps(self.state, ensure_ascii=False),),
        )
        self.db.commit()

    def identity(self):
        require(self.kube.identity() == self.settings["cluster_uid"], "cluster_changed")
        for side, uid in self.settings["namespace_uids"].items():
            require(self.kube.owned(side) == uid, "namespace_changed")

    def environment_digest(self):
        """Clusters, owned namespaces and the exact pods and images now running."""
        pods = {}
        for side in ("source", "target"):
            pods[side] = sorted(
                [
                    p["metadata"]["uid"],
                    p["metadata"].get("labels", {}).get("sova.io/role"),
                    [
                        c.get("imageID") or c.get("image")
                        for c in p.get("status", {}).get("containerStatuses", [])
                    ],
                ]
                for p in self.kube.get(side, "pods")["items"]
                if not p["metadata"].get("deletionTimestamp")
            )
        return sha(
            {
                "clusters": self.settings["cluster_uid"],
                "namespaces": self.settings["namespace_uids"],
                "pods": pods,
            }
        )

    def attested_verify(self, stage):
        """Verify, then sign the readback (PASS or FAIL) bound to plan and environment."""
        try:
            self.verify()
        except Unconfirmed:
            if self.state.get("checks"):
                self.sign_checks(stage)
            raise
        return self.sign_checks(stage)

    def sign_checks(self, stage):
        receipt = self.evidence.issue(
            run_id=self.state["run_id"],
            scenario=self.state["scenario"],
            stage=stage,
            revision=self.state["revision"],
            plan_digest=self.state["plan"]["digest"],
            environment=self.environment_digest(),
            checks=self.state["checks"],
        )
        self.state["evidence"].setdefault("signed", {})[stage] = receipt
        self.db.execute(
            "INSERT INTO journal(at,kind,body) VALUES(?,?,?)",
            (now(), "evidence", json.dumps(receipt, ensure_ascii=False)),
        )
        return receipt

    def image(self, side, version):
        """Pinned image reference for `version` on the cluster hosting `side`."""
        by_cluster = self.settings.get("images_by_cluster")
        if by_cluster:
            return by_cluster[placement(side)][version]
        return self.settings["images"][version]["image"]

    def topology(self):
        hybrid = PROFILE["name"] == "hybrid-aws"
        labels = {
            "source": "AWS EKS 출발지" if hybrid else "로컬 출발지",
            "target": "이 Mac 온프렘",
            "control": "로컬 제어",
        }
        db_hosts = {
            "db." + NAMESPACES["source"]: "source",
            "db." + NAMESPACES["target"]: "target",
        }
        if hybrid:
            db_hosts["source-db." + NAMESPACES["control"]] = "source"
        return {"name": PROFILE["name"], "labels": labels, "db_hosts": db_hosts}

    def admin(self, side, role, path, body):
        return self.kube.request(
            side, role, "/admin/" + path, body=body, admin=self.settings["admin"]
        )

    def sql(self, side, text, params=None):
        result = self.kube.sql(side, text, params, admin=True)
        require(result.get("ok"), "database_query_unconfirmed")
        return result["rows"]

    def fingerprint(self, side):
        messages = self.sql(
            side, 'SELECT id, body FROM messages ORDER BY id COLLATE "C"'
        )
        jobs = self.sql(
            side, 'SELECT id,body,completed FROM jobs ORDER BY id COLLATE "C"'
        )
        return {
            "sha256": digest([messages, jobs]),
            "messages": len(messages),
            "jobs": len(jobs),
            "completed": sum(row[2] for row in jobs),
        }

    def pods(self, side, role):
        return [
            item
            for item in self.kube.get(side, "pods")["items"]
            if item["metadata"].get("labels", {}).get("sova.io/role") == role
        ]

    def current_uids(self):
        return {
            side: {
                role: sorted(p["metadata"]["uid"] for p in self.pods(side, role))
                for role in ("api", "worker")
            }
            for side in ("source", "target")
        }

    def select(self, scenario):
        if scenario not in SCENARIOS:
            raise ValueError("unknown_scenario")
        with self.lock:
            if self.busy or self.state["phase"] != "normal":
                raise ValueError(
                    "현재 대응을 마친 뒤 response reset으로 초기화해 주세요."
                )
            if self.security.active():
                raise ValueError("security_hold_active_release_required")
            self.state["scenario"] = scenario
            self.state["revision"] += 1
            self.save()
            return self.status()

    def status(self):
        with self.lock:
            return {
                "kind": "sova.local-response.v1",
                "actual_execution": True,
                "scope": (
                    "개인 AWS 계정의 전용 EKS 출발지 · 이 Mac RKE2 목적지 · 팀 운영/T10 승인과 분리"
                    if PROFILE["name"] == "hybrid-aws"
                    else "이 Mac의 전용 RKE2 · 로컬 출발지/목적지 · 팀 운영/T10 승인과 분리"
                ),
                "topology": self.topology(),
                "support": self.support_view,
                "busy": self.busy,
                "session": json.loads(json.dumps(self.state)),
                "observation": self.observation,
            }

    def submit(self, body):
        if type(body) is not dict or set(body) != {"request_id", "revision", "command"}:
            raise ValueError("exact_command_required")
        import re

        if (
            not re.fullmatch("[a-f0-9]{32}", str(body["request_id"]))
            or type(body["revision"]) is not int
            or type(body["command"]) is not str
            or len(body["command"]) > 256
        ):
            raise ValueError("invalid_command")
        request_hash = digest(body)
        with self.lock:
            previous = self.db.execute(
                "SELECT request_hash,status FROM effects WHERE id=?",
                (body["request_id"],),
            ).fetchone()
            if previous:
                require(previous[0] == request_hash, "idempotency_conflict")
                return {
                    "accepted": True,
                    "duplicate": True,
                    "effect_status": previous[1],
                }
            if self.busy or body["revision"] != self.state["revision"]:
                raise ValueError("stale_or_busy_command")
            self.validate_command(body["command"])
            self.db.execute(
                "INSERT INTO effects VALUES(?,?,?,?)",
                (body["request_id"], request_hash, "started", json.dumps(body)),
            )
            self.db.commit()  # durable dispatch before the first external effect
            self.busy = True
            threading.Thread(target=self.execute, args=(body,), daemon=True).start()
            return {"accepted": True, "duplicate": False}

    def validate_command(self, command):
        if self.security.active():
            if not command.startswith("security release "):
                raise ValueError("security_hold_active_release_required")
            return
        if command.startswith("security hold "):
            return
        if command.startswith("security release "):
            raise ValueError("no_active_security_hold")
        phase = (
            self.state["recovery"]["phase"]
            if self.state["recovery"]
            else self.state["phase"]
        )
        signal, targets = SIGNALS[self.state["scenario"]]
        expected = {
            "normal": f"inject {signal} --target {targets}",
            "detected": "response plan",
            "planned": "response submit",
            "awaiting_approval": "response approve",
            "executing": "response verify",
            "verifying": "response finalize",
            "recovery_checking": "recovery verify",
            "recovery_restoring": "recovery finalize",
        }.get(phase)
        if command == "response reset":
            return
        if (
            command == "recovery start"
            and self.state["scenario"] in {"segment", "isolate"}
            and phase == "complete"
        ):
            return
        if (
            command == "exit drill"
            and self.state["scenario"] == "migrate"
            and phase == "complete"
            and "exit_drill" not in self.state["evidence"]
        ):
            return
        if command != expected:
            raise ValueError("command_not_allowed_in_current_phase")

    def execute(self, body):
        with self.lock:
            self.state["revision"] += 1
            self.save()
        try:
            self.identity()
            self.perform(body["command"])
            with self.lock:
                self.db.execute(
                    "UPDATE effects SET status='confirmed' WHERE id=?",
                    (body["request_id"],),
                )
        except Exception as error:
            if body["command"].startswith("security "):
                with self.lock:
                    self.event(
                        "security_rejected",
                        "보안 명령을 거부했습니다. 상태는 바뀌지 않았습니다: "
                        + (
                            str(error)[:160]
                            if isinstance(error, (Unconfirmed, ContractError))
                            else type(error).__name__
                        ),
                    )
                    self.db.execute(
                        "UPDATE effects SET status='rejected' WHERE id=?",
                        (body["request_id"],),
                    )
                return
            with self.lock:
                self.state["phase"] = "held"
                if self.state["recovery"]:
                    self.state["recovery"]["phase"] = "recovery_held"
                self.state["outcome"] = "unknown"
                self.event(
                    "held",
                    "실행 또는 검증을 확인하지 못해 보류했습니다. 자동 재시도하지 않습니다: "
                    + (
                        str(error)
                        if isinstance(error, Unconfirmed)
                        else type(error).__name__
                    ),
                )
                self.db.execute(
                    "UPDATE effects SET status='unknown' WHERE id=?",
                    (body["request_id"],),
                )
        finally:
            try:
                self.observe()
            except Exception:
                self.observation = {
                    "current": False,
                    "error": "observation_unavailable",
                    "observed_at": now(),
                }
            with self.lock:
                self.busy = False
                self.save()
                private_json(self.root / "latest-evidence.json", self.status())

    def phase(self, phase, message):
        with self.lock:
            self.state["phase"] = phase
            self.event(phase, message)
            self.save()

    def perform(self, command):
        if command.startswith("security hold "):
            hold = self.security.raise_hold(command.removeprefix("security hold "))
            self.event(
                "security_hold",
                "보안 보류를 걸었습니다. 해제 전에는 초기화를 포함한 모든 변경을 거부합니다: "
                + hold.hold_id,
            )
            return
        if command.startswith("security release "):
            released = self.security.release(command.removeprefix("security release "))
            self.db.execute(
                "INSERT INTO journal(at,kind,body) VALUES(?,?,?)",
                (
                    now(),
                    "security_release",
                    json.dumps(released.document, ensure_ascii=False),
                ),
            )
            self.event(
                "security_released",
                "등록된 별도 승인자의 서명으로 보안 보류를 해제했습니다. 이전 승인·증거는 재사용하지 않습니다: "
                + released.release.approved_by,
            )
            return
        if command == "response reset":
            self.reset()
            return
        if command == "exit drill":
            self.exit_drill()
            self.event(
                "exit_drilled",
                "출발지 경로를 끊은 상태에서 새 목적지 인스턴스가 쓰기 보류로 시작하고, 단일 writer 확인 뒤 업무 쓰기·읽기가 되는 것을 확인했습니다. 경로는 복원했습니다.",
            )
            return
        if command.startswith("inject "):
            self.inject()
            self.phase(
                "detected",
                "통제된 시험 신호를 실제 앱에서 확인했습니다. 일반 공격 탐지 결과와 구분합니다.",
            )
        elif command == "response plan":
            binding = {
                "cluster_uid": self.settings["cluster_uid"],
                "namespace_uids": self.settings["namespace_uids"],
                "scenario": self.state["scenario"],
                "run_id": self.state["run_id"],
                "pods": self.current_uids(),
                "created_at": time.time(),
                "expires_at": time.time() + 300,
            }
            self.state["plan"] = {"binding": binding, "digest": digest(binding)}
            self.phase(
                "planned",
                "현재 Pod UID·두 실행 영역·대응 유형을 고정한 계획을 만들었습니다.",
            )
        elif command == "response submit":
            self.phase(
                "awaiting_approval",
                "이 Mac의 전용 앱에 적용할 계획의 명시 승인을 기다립니다.",
            )
        elif command == "response approve":
            plan = self.state["plan"]
            require(
                plan
                and digest(plan["binding"]) == plan["digest"]
                and time.time() < plan["binding"]["expires_at"],
                "plan_expired_or_modified",
            )
            require(
                self.current_uids() == plan["binding"]["pods"],
                "workload_changed_replan_required",
            )
            self.state["approved"] = True
            self.state["evidence"]["before_uids"] = self.current_uids()
            self.respond()
            self.phase(
                "executing",
                "승인된 실제 변경을 적용했습니다. 독립적인 결과 검증은 다음 명령에서 수행합니다.",
            )
        elif command == "response verify":
            self.attested_verify("verify")
            self.phase(
                "verifying",
                "실제 HTTP·DB·Pod·정책 결과를 확인했습니다. 최종 명령 전에는 전환 완료로 표시하지 않습니다.",
            )
        elif command == "response finalize":
            require(
                self.state["checks"]
                and all(item["passed"] for item in self.state["checks"]),
                "checks_not_passed",
            )
            # Fresh readback immediately before the final effect. Both the
            # verify-time and this envelope must still bind to the approved
            # plan and to the environment as observed right now.
            final = self.attested_verify("finalize")
            environment = self.environment_digest()
            plan = self.state["plan"]["digest"]
            try:
                for receipt in (self.state["evidence"]["signed"]["verify"], final):
                    self.evidence.accept(
                        receipt, plan_digest=plan, environment=environment
                    )
            except (ContractError, KeyError, OSError, ValueError) as error:
                raise Unconfirmed(
                    "signed_evidence_rejected: " + str(error)[:120]
                ) from error
            self.finalize()
            self.state["outcome"] = "pass"
            self.phase(
                "complete",
                "이 로컬 실행 범위의 결과 확인을 마쳤습니다. 시험 기록과 사고 보류는 보존합니다.",
            )
        elif command == "recovery start":
            self.state["recovery"] = {
                "phase": "recovery_checking",
                "outcome": "unknown",
            }
            self.event(
                "recovery_checking",
                "선택 구간의 복귀 조건을 확인합니다. 차단은 유지합니다.",
            )
        elif command == "recovery verify":
            self.recover_prepare()
            self.state["recovery"]["phase"] = "recovery_restoring"
            self.event(
                "recovery_restoring",
                "원본을 제한된 상태에서 준비했습니다. 원본 연결 확인 후 복귀합니다.",
            )
        elif command == "recovery finalize":
            self.recover_finalize()
            self.state["recovery"] = {"phase": "recovered", "outcome": "pass"}
            self.event(
                "recovered",
                "원본 앱 응답·DB·경로 복귀를 확인했습니다. 사고 이력은 남깁니다.",
            )
