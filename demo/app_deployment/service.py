"""Host-owned deployment jobs, with no auto-retry of uncertain external effects."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import secrets
import threading

from .intake import unpack, github_archive
from .builder import build, run
from .aws_target import AwsTarget


def save(path, value):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False))
    tmp.chmod(0o600)
    tmp.replace(path)


class Apps:
    def __init__(self, root, settings, *, team_load=None):
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.stat().st_mode & 0o077 or self.root.stat().st_uid != os.getuid():
            raise ValueError("private_app_storage_required")
        self.team_load = team_load
        self.settings = settings
        self.lock = threading.RLock()
        self.pool = ThreadPoolExecutor(max_workers=1)
        for f in self.root.glob("*/state.json"):
            d = json.loads(f.read_text())
            if d["phase"] in {
                "queued",
                "building",
                "publishing",
                "deploying",
                "publishing_url",
            }:
                d.update(
                    phase="attention",
                    detail="호스트가 재시작됐습니다. 실제 자원 확인 전 재실행하지 않습니다.",
                )
                save(f, d)

    def states(self):
        with self.lock:
            return [
                json.loads(p.read_text())
                for p in sorted(self.root.glob("*/state.json"))
            ]

    def team_app(self):
        if self.team_load is None:
            return None
        from .team_app import project_team_app

        return project_team_app(self.team_load())

    def folder(self, app_id):
        if not re.fullmatch(r"[a-f0-9]{16}", app_id):
            raise ValueError("invalid_app_id")
        return self.root / app_id

    def ingest(self, data, origin):
        with self.lock:
            if len(list(self.root.iterdir())) >= 20:
                raise ValueError("operator_app_limit_reached")
            app_id = secrets.token_hex(8)
            folder = self.folder(app_id)
            folder.mkdir(mode=0o700)
        try:
            source = unpack(data, folder / "source")
            # Reject source credentials before any upload to a registry or cloud.
            run(
                [
                    self.settings["gitleaks"],
                    "dir",
                    str(source.root),
                    "--redact",
                    "--no-banner",
                ],
                timeout=90,
            )
            save(
                folder / "source.json",
                {
                    "root": str(source.root),
                    "digest": source.digest,
                    "file_count": source.file_count,
                    "runtime": source.runtime,
                    "entry": source.entry,
                },
            )
            state = {
                "id": app_id,
                "phase": "ready_to_deploy",
                "runtime": source.runtime,
                "source_digest": source.digest,
                "file_count": source.file_count,
                "origin": origin,
                "detail": "소스 검사 완료. AWS 배포와 공개 접속 여부를 선택하세요.",
                "updated_at": datetime.now(UTC).isoformat(),
                "events": [],
                "workload": None,
                "public_url": None,
            }
            save(folder / "state.json", state)
            return state
        except Exception:
            save(
                folder / "rejected.json",
                {"reason": "source_rejected", "at": datetime.now(UTC).isoformat()},
            )
            raise

    def github(self, repository, ref):
        data, origin = github_archive(repository, ref)
        return self.ingest(data, origin)

    def update(self, app_id, phase, detail, **values):
        with self.lock:
            path = self.folder(app_id) / "state.json"
            state = json.loads(path.read_text())
            at = datetime.now(UTC).isoformat()
            state.update(phase=phase, detail=detail, updated_at=at, **values)
            state["events"].append({"phase": phase, "detail": detail, "at": at})
            save(path, state)

    def deploy(self, app_id, source_digest, health, public):
        if not isinstance(public, bool) or not re.fullmatch(
            r"/[A-Za-z0-9/_-]*", health
        ):
            raise ValueError("invalid_deployment_options")
        with self.lock:
            state = json.loads((self.folder(app_id) / "state.json").read_text())
            if (
                state["phase"] != "ready_to_deploy"
                or state["source_digest"] != source_digest
            ):
                raise ValueError("source_changed_or_already_dispatched")
            self.update(
                app_id,
                "queued",
                "AWS 출발지 배포 요청 접수",
                health_path=health,
                public_requested=public,
            )
            self.pool.submit(self.execute, app_id, health, public)
        return {"id": app_id, "phase": "queued"}

    def execute(self, app_id, health, public):
        from .intake import Source

        folder = self.folder(app_id)
        try:
            source = json.loads((folder / "source.json").read_text())
            source["root"] = Path(source["root"])
            source = Source(**source)
            target = AwsTarget(self.settings)
            target.verify()
            self.update(app_id, "building", "소스 해시·잠금 의존성으로 격리 빌드 중")
            built = build(
                source,
                folder,
                base=self.settings["runtime_images"][source.runtime],
                platform="linux/amd64",
            )
            save(folder / "build.json", built)
            self.update(app_id, "publishing", "불변 이미지 저장소에 업로드 중")
            image = target.publish(built, app_id)
            save(folder / "image.json", {"image": image})
            self.update(
                app_id, "deploying", "AWS EKS에서 앱 기동·이미지·HTTP 응답 확인 중"
            )
            workload = target.deploy(app_id, image, health, source.digest)
            save(folder / "workload.json", workload)
            self.update(
                app_id,
                "running",
                "AWS 앱의 이미지·Pod 준비 상태·HTTP 응답을 확인했습니다.",
                workload=workload,
            )
            if public:
                self.update(
                    app_id, "publishing_url", "Cloudflare 임시 공개 주소 연결 중"
                )
                url = target.publish_url(app_id, self.settings["tunnel_image"])
                self.update(
                    app_id,
                    "running",
                    "AWS 앱과 Cloudflare 공개 HTTPS 응답 확인 완료",
                    public_url=url,
                )
        except Exception as e:
            # Never forward command output, credentials or arbitrary source errors.
            self.update(
                app_id,
                "attention",
                "실제 배포 상태 확인이 필요합니다. 자원을 자동 삭제하거나 재실행하지 않습니다.",
                error_code=type(e).__name__,
            )
