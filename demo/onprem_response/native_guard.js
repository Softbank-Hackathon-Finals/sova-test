// A UI restriction, never execution authority. T10 still decides every request.
let windowScope = null;
const routes = {
  "approve-change": ["approvals", "change"],
  approve: ["approvals", "cutover"],
  "op-shift": ["approvals", "shift"],
  "op-failback-approve": ["approvals", "failback"],
  execute: ["cutover"],
  "op-failback-submit": ["failback"],
};
function currentWindow() {
  return windowScope && Date.now() < Date.parse(windowScope.expires_at)
    ? windowScope
    : null;
}
function lock() {
  const w = currentWindow();
  const plan = document.getElementById("plan")?.value;
  for (const b of document.querySelectorAll("button")) {
    if (b.closest("nav") || b.closest("#connect-form")) continue;
    const route = routes[b.id];
    const allowed =
      w &&
      w.plan_id === plan &&
      route &&
      w.routes.includes(route[0]) &&
      (!route[1] || w.approval_kinds.includes(route[1]));
    // Never enable a button that the native model disabled.
    if (!allowed && !b.disabled) b.disabled = true;
  }
  const status = document.getElementById("native-transport-status");
  const text = w
    ? `계획 ${w.plan_id}의 합의된 실행 구간만 연결됩니다. T10이 권한·승인 결속을 다시 검사합니다. 기한: ${new Date(w.expires_at).toLocaleString("ko-KR")}`
    : "실제 T10 계획·SSE 조회 연결입니다. 운영 변경은 실행 구간 인수 전까지 잠겨 있습니다. 권한 거부 시 계획이나 승인을 생성하지 않습니다.";
  if (status && status.textContent !== text) status.textContent = text;
}
async function refreshScope() {
  try {
    const response = await fetch("/__native/status", {
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) throw Error("native_session_required");
    const value = await response.json();
    if (
      value.kind !== "native-console-transport.v1" ||
      value.native_authorization_required !== true
    )
      throw Error("invalid_scope");
    const w = value.window;
    if (
      w &&
      (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(w.plan_id) ||
        !Number.isFinite(Date.parse(w.expires_at)) ||
        !Array.isArray(w.routes) ||
        !Array.isArray(w.approval_kinds))
    )
      throw Error("invalid_window");
    windowScope = w;
  } catch {
    windowScope = null;
  }
  lock();
}
new MutationObserver(lock).observe(document.body, {
  subtree: true,
  childList: true,
  attributes: true,
  attributeFilter: ["disabled"],
});
document.getElementById("plan")?.addEventListener("input", lock);
lock();
refreshScope();
setInterval(refreshScope, 5000);
setInterval(lock, 1000);
