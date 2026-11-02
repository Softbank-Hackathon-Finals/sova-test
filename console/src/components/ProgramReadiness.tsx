import { useEffect, useState } from "react";
import { CircleHelp, FileCheck2 } from "lucide-react";
import { request } from "../api";
import { readiness } from "../readiness";
import type { Readiness } from "../readiness";

export function ProgramReadiness() {
  const [data, setData] = useState<Readiness | null>(null);
  const [received, setReceived] = useState(0);
  const [tick, setTick] = useState(Date.now());
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    let busy = false;
    let controller: AbortController | null = null;
    async function load() {
      if (busy) return;
      busy = true;
      controller = new AbortController();
      const timer = setTimeout(() => controller?.abort(), 9000);
      try {
        const next = readiness(
          await request<unknown>(
            "/api/migration/readiness",
            undefined,
            controller.signal,
          ),
        );
        if (active) {
          setData(next);
          setError("");
          setReceived(Date.now());
        }
      } catch (e) {
        if (active) {
          setReceived(0);
          setError(e instanceof Error ? e.message : "검증 목록 연결 미확인");
        }
      } finally {
        clearTimeout(timer);
        busy = false;
      }
    }
    void load();
    const poll = setInterval(() => void load(), 5000);
    const clock = setInterval(() => setTick(Date.now()), 1000);
    return () => {
      active = false;
      controller?.abort();
      clearInterval(poll);
      clearInterval(clock);
    };
  }, []);
  const current =
    !!received &&
    tick - received < 12000 &&
    data?.status === "connected" &&
    tick < Date.parse(data.expires_at || "");
  const areas = current ? data.report!.areas : data?.catalog || [];
  return (
    <section
      className="panel program-readiness"
      aria-label="여섯 영역 검증 의무"
    >
      <div className="panel-heading">
        <FileCheck2 size={19} />
        <h2>전체 이전에 필요한 여섯 영역</h2>
      </div>
      <p>
        경로 전환 성공과 전체 이전 완료를 구분합니다. 아래는 같은 실행본에
        연결해야 할 필수 검증 의무이며, 화면에서 실행 권한을 부여하지 않습니다.
      </p>
      {error && <p role="status">{error}</p>}
      {!current && (
        <p className="readiness-warning">
          <CircleHelp size={14} />
          현재 근거 미확인 · 목록과 과거 이력이 있더라도 통과로 표시하지
          않습니다.
        </p>
      )}
      <div className="readiness-grid">
        {areas.map((area) => {
          const verified = current
            ? area.requirements.filter(
                (r) => r.result === "pass" || r.result === "not_applicable",
              ).length
            : 0;
          return (
            <article key={area.id} className="readiness-area">
              <h3>{area.title}</h3>
              <strong>
                {verified} / {area.requirements.length} 조건 근거
              </strong>
              <details>
                <summary>요구사항·근거 보기</summary>
                <ul>
                  {area.requirements.map((req) => (
                    <li key={req.id}>
                      <span
                        className={`readiness-result ${current ? req.result || "unknown" : "unknown"}`}
                      >
                        {current && req.result === "pass"
                          ? "확인"
                          : current && req.result === "fail"
                            ? "미충족"
                            : current && req.result === "not_applicable"
                              ? "적용 제외 승인"
                              : "미검증"}
                      </span>
                      <span>
                        {req.objective}
                        <small>
                          G{req.due_gate} ·{" "}
                          {req.evidence_id || "연결된 검증 근거 없음"}
                        </small>
                      </span>
                    </li>
                  ))}
                </ul>
              </details>
            </article>
          );
        })}
      </div>
      <p className="panel-note">
        현재 AWS·VM 시험의 실제 요청 응답만 이 실행의 근거로 연결합니다. 다른
        로컬 Kubernetes 앱의 보안 결과나 단위시험 결과를 이 앱의 검증 통과로
        재사용하지 않습니다.
      </p>
    </section>
  );
}
