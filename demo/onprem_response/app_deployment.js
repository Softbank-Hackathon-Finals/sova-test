const el = (tag, text, cls) => {
  const n = document.createElement(tag);
  if (text !== undefined) n.textContent = text;
  if (cls) n.className = cls;
  return n;
};
export function mountApps(parent) {
  const box = el("section", undefined, "card sova-live-card");
  box.append(
    el("p", "DEPLOY YOUR APPLICATION", "eyebrow"),
    el("h2", "앱 등록 · AWS에 배포"),
    el(
      "p",
      "팀 demo-app의 현재 배포를 사용하거나 ZIP·공개 GitHub 소스로 새 앱을 등록합니다.",
    ),
  );
  const form = el("div", undefined, "sova-app-form");
  const zip = el("input");
  zip.type = "file";
  zip.accept = ".zip,application/zip";
  zip.setAttribute("aria-label", "앱 ZIP 파일");
  const upload = el("button", "ZIP 등록", "sova-live-link");
  upload.type = "button";
  const repo = el("input");
  repo.type = "url";
  repo.placeholder = "https://github.com/owner/repository";
  repo.setAttribute("aria-label", "공개 GitHub 저장소");
  const ref = el("input");
  ref.value = "main";
  ref.setAttribute("aria-label", "GitHub 브랜치 또는 커밋");
  const github = el("button", "GitHub 연결", "sova-live-link");
  github.type = "button";
  form.append(
    el("h3", "소스 선택"),
    zip,
    upload,
    el("h3", "또는 공개 GitHub 저장소"),
    repo,
    ref,
    github,
  );
  box.append(
    form,
    el(
      "p",
      "지원: 정적 사이트, package-lock.json과 main 파일이 있는 Node HTTP 앱(8080). 빌드·설치 스크립트는 실행하지 않습니다. 로컬 DB 파일은 영속 저장소 설정이 필요하므로 일반 업로드에서 거부합니다.",
      "muted",
    ),
  );
  const feedback = el("p", "", "muted");
  feedback.setAttribute("role", "status");
  box.append(feedback);
  const team = el("section", undefined, "sova-team-app");
  box.prepend(team);
  const list = el("div");
  box.append(list);
  parent.append(box);
  let working = false,
    timer;
  async function post(path, body, zipBody = false) {
    const r = await fetch("/__apps/" + path, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": zipBody ? "application/zip" : "application/json",
      },
      body: zipBody ? body : JSON.stringify(body),
    });
    const v = await r.json();
    if (!r.ok) throw Error(v.detail || "요청을 처리하지 못했습니다.");
    return v;
  }
  async function action(fn) {
    if (working) return;
    working = true;
    upload.disabled = github.disabled = true;
    feedback.textContent = "요청 처리 중";
    try {
      await fn();
      feedback.textContent = "요청을 접수했습니다.";
      await refresh();
    } catch (e) {
      feedback.textContent = e.message;
    } finally {
      working = false;
      upload.disabled = github.disabled = false;
    }
  }
  upload.onclick = () =>
    action(async () => {
      if (!zip.files[0] || zip.files[0].size > 20 * 1024 * 1024)
        throw Error("20MB 이하 ZIP을 선택하세요.");
      await post("zip", zip.files[0], true);
    });
  github.onclick = () =>
    action(() =>
      post("github", { repository: repo.value.trim(), ref: ref.value.trim() }),
    );
  const phases = {
    ready_to_deploy: "배포 준비",
    queued: "요청 접수",
    building: "빌드 중",
    publishing: "이미지 업로드 중",
    deploying: "AWS 기동 확인 중",
    publishing_url: "공개 주소 연결 중",
    running: "AWS 앱 실행 확인",
    attention: "상태 확인 필요",
  };
  async function refresh() {
    if (!box.isConnected) {
      clearInterval(timer);
      return;
    }
    try {
      const r = await fetch("/__apps/status", {
        cache: "no-store",
        credentials: "same-origin",
      });
      if (!r.ok) throw Error("앱 배포 호스트 연결·개인 세션을 확인하세요.");
      const d = await r.json();
      team.replaceChildren();
      if (d.team_app) {
        const app = d.team_app;
        team.append(
          el("p", "REGISTERED TEAM APPLICATION", "eyebrow"),
          el("h2", app.name),
          el(
            "p",
            "AWS에 배포된 실제 팀 앱을 출발지로 사용합니다. 온프렘 배포 관측과 이전 완료 여부를 각각 확인합니다.",
          ),
        );
        const repoLink = el("a", "팀 저장소 열기 ↗", "sova-live-link");
        repoLink.href = "https://github.com/Softbank-Hackathon-Finals/demo-app";
        repoLink.target = "_blank";
        repoLink.rel = "noopener noreferrer";
        team.append(
          repoLink,
          el("p", "저장소 기준: " + app.repository_revision),
        );
        const lanes = el("div", undefined, "sova-migration-lanes");
        for (const env of app.environments) {
          const lane = el("article", undefined, "sova-migration-lane");
          lane.dataset.current = String(env.current);
          lane.append(
            el(
              "h3",
              env.lane === "source" ? "AWS · 출발지" : "온프렘 RKE2 · 목적지",
            ),
            el(
              "strong",
              env.current ? "실제 앱 관측 수신" : "현재 앱 상태 미확인",
            ),
          );
          if (env.current)
            lane.append(
              el("p", `Ready ${env.ready_replicas} / ${env.desired_replicas}`),
              el("p", "HTTP: " + (env.http_status || "미확인")),
            );
          if (env.current && env.application_info) {
            lane.append(
              el("p", "앱 환경: " + (env.application_info.env || "미확인")),
              el(
                "p",
                env.application_info.write_blocked === true
                  ? "업무 쓰기 차단 활성"
                  : env.application_info.write_blocked === false
                    ? "앱 쓰기 차단 해제 상태 · DB writer 검증은 별도"
                    : "앱 쓰기 상태 미확인",
              ),
            );
          }
          lane.append(
            el(
              "small",
              env.observed_at
                ? "관측 " +
                    new Date(env.observed_at).toLocaleTimeString("ko-KR")
                : "관측 없음",
            ),
          );
          const ids = el("details");
          ids.append(el("summary", "실행 이미지·자원 근거"));
          for (const image of env.images) ids.append(el("p", image));
          if (env.current)
            for (const uid of env.pod_uids)
              ids.append(el("p", "Pod UID: " + uid));
          lane.append(ids);
          lanes.append(lane);
        }
        team.append(
          lanes,
          el(
            "p",
            "저장소 최신 커밋과 실행 이미지의 일치 여부는 미확인입니다. 운영 이전·격리 완료는 실행 근거를 인수한 뒤 표시합니다.",
            "muted",
          ),
        );
      }
      list.replaceChildren();
      for (const app of d.apps) {
        const card = el("article", undefined, "sova-migration-resource");
        card.append(
          el("h3", `${app.runtime} 앱 · ${app.id}`),
          el("strong", phases[app.phase] || "상태 미확인"),
          el("p", app.detail),
          el("small", "소스 SHA-256: " + app.source_digest),
        );
        if (app.phase === "ready_to_deploy") {
          const health = el("input");
          health.value = app.runtime === "static" ? "/" : "/health";
          health.setAttribute("aria-label", "HTTP 상태 확인 경로");
          const check = el("input");
          check.type = "checkbox";
          const label = el("label");
          label.append(
            check,
            document.createTextNode(
              " Cloudflare 임시 주소로 앱 공개 (로그인 제한 없음)",
            ),
          );
          const deploy = el("button", "AWS 출발지에 배포", "sova-live-link");
          deploy.type = "button";
          deploy.onclick = () => {
            deploy.disabled = true;
            action(() =>
              post("deploy", {
                id: app.id,
                source_digest: app.source_digest,
                health: health.value,
                public: check.checked,
              }),
            );
          };
          card.append(el("p", "상태 확인 경로"), health, label, deploy);
        }
        if (app.workload) {
          const w = app.workload;
          card.append(
            el(
              "p",
              `${w.environment} · Ready ${w.ready_replicas}개 · HTTP 확인됨`,
            ),
            el("p", "실제 namespace: " + w.namespace),
          );
          const ids = el("details");
          ids.append(
            el("summary", "실제 이미지·워크로드 식별 근거"),
            el("p", w.image),
            el("p", "Service UID: " + w.service_uid),
          );
          for (const uid of w.pod_uids) ids.append(el("p", "Pod UID: " + uid));
          card.append(ids);
          card.append(
            el(
              "p",
              "온프렘 이전·자동 격리는 아직 실행하지 않았습니다.",
              "muted",
            ),
          );
        }
        if (app.public_url) {
          const a = el("a", "배포 앱 열기 ↗", "sova-live-link");
          const u = new URL(app.public_url);
          if (
            u.protocol === "https:" &&
            /^[a-z0-9-]+\.trycloudflare\.com$/.test(u.hostname)
          ) {
            a.href = u.href;
            a.target = "_blank";
            a.rel = "noopener noreferrer";
            card.append(a);
          }
          card.append(
            el("small", "임시 주소: 터널 재시작 시 바뀔 수 있습니다."),
          );
        }
        const events = el("details");
        events.append(el("summary", "배포 기록"));
        for (const e of app.events)
          events.append(
            el(
              "p",
              new Date(e.at).toLocaleTimeString("ko-KR") + " · " + e.detail,
            ),
          );
        card.append(events);
        list.append(card);
      }
      if (!d.apps.length)
        list.append(
          el(
            "p",
            "아직 등록한 앱이 없습니다. ZIP 또는 GitHub 소스를 연결하세요.",
          ),
        );
    } catch (e) {
      list.replaceChildren();
      feedback.textContent = e.message;
    }
  }
  refresh();
  timer = setInterval(() => {
    if (!box.contains(document.activeElement)) refresh();
  }, 5000);
}
