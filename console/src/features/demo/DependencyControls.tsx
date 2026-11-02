import {
  ArrowUpRight,
  Check,
  LockKeyhole,
  RefreshCw,
  TriangleAlert,
} from "lucide-react";
import type { DependencyState } from "../../types";
import { request } from "../../api";

interface Props {
  dependency: DependencyState | null;
  selected: string[];
  disabled: boolean;
  pending: boolean;
  faultTarget: string;
  choose: (id: string) => void;
  setSelected: (ids: string[]) => void;
  setFaultTarget: (id: string) => void;
  processAction: (
    action: string,
    ids: string[],
    title: string,
    description: string,
    danger?: boolean,
  ) => void;
  execute: (action: () => Promise<unknown>) => Promise<void>;
}
export function DependencyControls({
  dependency,
  selected,
  disabled,
  pending,
  faultTarget,
  choose,
  setSelected,
  setFaultTarget,
  processAction,
  execute,
}: Props) {
  const selectedIsolated = selected.filter(
    (id) => dependency?.nodes.find((n) => n.id === id)?.state === "isolated",
  );
  const selectedRunning = selected.filter(
    (id) => dependency?.nodes.find((n) => n.id === id)?.state !== "isolated",
  );
  const target = dependency?.nodes.find((n) => n.id === faultTarget);
  return (
    <>
      <div className="control-section">
        <div className="section-label">
          <span>01</span>선택 구간
        </div>
        <div className="node-picker">
          {dependency?.nodes.map((n) => (
            <button
              key={n.id}
              onClick={() => choose(n.id)}
              aria-pressed={selected.includes(n.id)}
              disabled={pending}
            >
              <span
                className={`pick-box ${selected.includes(n.id) ? "checked" : ""}`}
              >
                {selected.includes(n.id) && <Check size={10} />}
              </span>
              {n.name}
            </button>
          ))}
        </div>
        <div className="selection-summary">
          <span>{selected.length}개 선택됨</span>
          <button className="text-button" onClick={() => setSelected([])}>
            선택 해제
          </button>
        </div>
        <button
          className="button danger-outline full"
          disabled={disabled || !selectedRunning.length}
          onClick={() =>
            processAction(
              "isolate",
              selectedRunning,
              "선택한 프로세스를 격리할까요?",
              "선택한 로컬 시험 프로세스만 종료합니다. 실제 방화벽이나 Kubernetes 자원을 변경하지 않습니다.",
              true,
            )
          }
        >
          <LockKeyhole size={15} />
          선택 구간 격리 <span>{selectedRunning.length}</span>
        </button>
        <button
          className="button secondary full"
          disabled={disabled || !selectedIsolated.length}
          onClick={() =>
            processAction(
              "restore",
              selectedIsolated,
              "선택한 프로세스를 복원할까요?",
              "종료된 시험 프로세스를 다시 기동하고 실제 응답을 재검증합니다.",
            )
          }
        >
          <RefreshCw size={15} />
          복원·재검증
        </button>
      </div>
      <div className="control-section">
        <div className="section-label">
          <span>02</span>통제된 장애 시험
        </div>
        <select
          className="field-select"
          aria-label="장애 주입 대상"
          value={faultTarget}
          onChange={(e) => setFaultTarget(e.target.value)}
          disabled={disabled}
        >
          {dependency?.nodes.map((n) => (
            <option key={n.id} value={n.id}>
              {n.name}
            </option>
          ))}
        </select>
        <div className="button-row">
          <button
            className="button secondary"
            disabled={
              disabled ||
              !target ||
              target.state === "isolated" ||
              target.observation.fault
            }
            onClick={() =>
              processAction(
                "fault",
                [faultTarget],
                "HTTP 오류를 주입할까요?",
                "선택한 시험 구성 요소가 실제 HTTP 503을 반환하도록 설정합니다. 실제 공격은 수행하지 않습니다.",
                true,
              )
            }
          >
            <TriangleAlert size={14} />
            장애 주입
          </button>
          <button
            className="button secondary"
            disabled={
              disabled ||
              !target?.observation.fault ||
              target.state === "isolated"
            }
            onClick={() =>
              processAction(
                "clear_fault",
                [faultTarget],
                "장애 설정을 해제할까요?",
                "시험 오류를 해제하고 새 요청으로 결과를 확인합니다.",
              )
            }
          >
            <Check size={14} />
            장애 해제
          </button>
        </div>
      </div>
      <button
        className="button primary full"
        disabled={disabled}
        onClick={() =>
          void execute(() =>
            request("/api/dependency/action", { action: "probe", nodes: [] }),
          )
        }
      >
        <ArrowUpRight size={16} />
        실제 업무 요청 확인
      </button>
    </>
  );
}
