import { Component } from "react";
import type { ReactNode, ErrorInfo } from "react";

export class Boundary extends Component<
  { children: ReactNode },
  { failed: boolean }
> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  componentDidCatch(_error: Error, _info: ErrorInfo) {
    /* Do not export runtime payloads or credentials. */
  }
  render() {
    if (this.state.failed)
      return (
        <main className="fatal-state">
          <h1>화면 상태를 확인할 수 없습니다.</h1>
          <p>
            변경 동작을 중단했습니다. 서버 상태를 확인한 뒤 화면을 다시
            불러오세요.
          </p>
          <button
            className="button secondary"
            onClick={() => location.reload()}
          >
            화면 다시 불러오기
          </button>
        </main>
      );
    return this.props.children;
  }
}
