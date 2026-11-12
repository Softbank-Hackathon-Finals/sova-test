let csrf = null;
const status = document.getElementById("app-state");
const error = document.getElementById("app-error");
async function request(path, body) {
  const r = await fetch(path, {credentials: "same-origin", cache: "no-store", ...(body ? {method: "POST", headers: {"Content-Type": "application/json", "X-Sova-CSRF": csrf}, body: JSON.stringify(body)} : {})});
  const v = await r.json();
  if (!r.ok) throw Error(v.error || "실제 앱 응답을 확인하지 못했습니다.");
  return v;
}
async function refresh() {
  const v = await request("/api/app");
  if (v.status !== 200) throw Error("업무 경로 응답이 없습니다. 격리·전환 중인지 확인해 주세요.");
  status.textContent = `${v.body.environment === "local-target" ? "이 Mac 온프렘 목적지" : "로컬 출발지"} · ${v.body.release} · Pod ${v.body.pod_uid}`;
  document.getElementById("messages").replaceChildren(...v.body.messages.map(message => {
    const li = document.createElement("li");
    li.textContent = message.body;
    li.style.padding = "12px";
    return li;
  }));
}
document.getElementById("message-form").onsubmit = async event => {
  event.preventDefault();
  error.textContent = "";
  const button = event.submitter;
  button.disabled = true;
  try {
    await request("/api/message", {id: crypto.randomUUID().replaceAll("-", ""), body: document.getElementById("message").value});
    document.getElementById("message").value = "";
    await refresh();
  } catch (e) { error.textContent = e.message; }
  finally { button.disabled = false; }
};
try {
  csrf = (await request("/api/session")).csrf;
  await refresh();
  const timer = setInterval(() => refresh().catch(e => { status.textContent = e.message; }), 4000);
  window.addEventListener("pagehide", () => clearInterval(timer), {once: true});
} catch (e) { error.textContent = e.message; }
