"use strict";
const $ = (id) => document.getElementById(id);
let proof = sessionStorage.getItem("consultation-proof") || "",
  room = null,
  socket = null,
  cursor = 0,
  generation = 0;
const messages = new Map(),
  outbox = new Map();
function status(text) {
  $("status").textContent = text;
}
async function api(path, body, options = {}) {
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: {
      "X-Consultation-CSRF": proof,
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(8000),
    ...options,
  });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    const e = Error(data.error || "요청 결과 미확인");
    e.status = response.status;
    throw e;
  }
  return response;
}
function add(items) {
  for (const m of items) messages.set(m.id, m);
  $("messages").replaceChildren();
  for (const m of [...messages.values()].sort(
    (a, b) => BigInt(a.sequence) < BigInt(b.sequence) ? -1 : BigInt(a.sequence) > BigInt(b.sequence) ? 1 : 0,
  )) {
    const li = document.createElement("li"),
      text = document.createElement("span"),
      meta = document.createElement("small");
    text.textContent = m.content;
    meta.textContent = `#${m.sequence} · ${m.environment} · epoch ${m.writer_epoch} · ${new Date(m.created_at).toLocaleTimeString()}`;
    li.append(text, meta);
    $("messages").append(li);
  }
  $("messages").scrollTop = $("messages").scrollHeight;
}
function stream() {
  if (socket) {
    const previous=socket;
    socket=null;
    previous.close();
  }
  if (!room || !proof) return;
  const version = generation;
  const url = new URL(
    `/api/rooms/${room}/stream?after=${cursor}`,
    location.href,
  );
  url.protocol = location.protocol === "https:" ? "wss:" : "ws:";
  const current = new WebSocket(url, ["consultation", proof]);
  socket = current;
  current.onopen = () => {
    if (socket !== current || version !== generation) return;
    $("connection").textContent = "실시간 연결";
  };
  current.onmessage = (event) => {
    if (version !== generation || socket !== current) return;
    const data = JSON.parse(event.data);
    add(data.messages);
    cursor = data.cursor;
    $("environment").textContent = `현재 응답: ${data.environment}`;
  };
  current.onclose = () => {
    if (version !== generation || socket !== current) return;
    socket=null;
    $("connection").textContent = "연결 끊김 · 마지막 수신 지점부터 재접속";
    setTimeout(() => {
      if (version === generation && socket === null) stream();
    }, 2000);
  };
  current.onerror = () => current.close();
}
async function choose(id) {
  generation++;
  room = id;
  cursor = 0;
  messages.clear();
  $("messages").replaceChildren();
  $("attachment").replaceChildren();
  $("room-title").textContent = "상담 " + id.slice(0, 8);
  $("summary-result").textContent = "";
  stream();
}
async function load() {
  const user = await (await api("/api/me")).json();
  $("identity").textContent = user.display_name;
  $("new-room").hidden = user.role !== "customer";
  $("summary").hidden = user.role !== "counselor";
  const rooms = await (await api("/api/rooms")).json();
  $("rooms").replaceChildren();
  for (const r of rooms) {
    const b = document.createElement("button");
    b.textContent = "상담 " + r.id.slice(0, 8);
    b.onclick = () => void choose(r.id);
    $("rooms").append(b);
  }
  $("login").hidden = true;
  $("workspace").hidden = false;
  $("logout").hidden = false;
  if (rooms.length && !room) await choose(rooms[0].id);
}
async function login(code) {
  const response = await api("/api/session", { invite: code });
  const result = await response.json();
  proof = result.csrf;
  sessionStorage.setItem("consultation-proof", proof);
  $("invite").value = "";
  await load();
}
$("login-form").onsubmit = (event) => {
  event.preventDefault();
  void login($("invite").value)
    .then(() => status(""))
    .catch((e) => status(e.message));
};
$("logout").onclick = async () => {
  try {
    await api("/api/logout", {});
  } catch {}
  generation++;
  room = null;
  if (socket) socket.close();
  proof = "";
  sessionStorage.removeItem("consultation-proof");
  messages.clear();
  outbox.clear();
  $("workspace").hidden = true;
  $("login").hidden = false;
  $("logout").hidden = true;
};
$("new-room").onclick = () =>
  void api("/api/rooms", {})
    .then((r) => r.json())
    .then(async (r) => {
      await load();
      await choose(r.id);
    })
    .catch((e) => status(e.message));
$("message-form").onsubmit = async (event) => {
  event.preventDefault();
  if (!room) return;
  if (new TextEncoder().encode($("content").value).length > 8192) {
    status("메시지는 UTF-8 기준 8KB 이하로 입력하세요.");
    return;
  }
  const version = generation,
    target = room,
    body = outbox.get(room) || {
      client_request_id: crypto.randomUUID(),
      content: $("content").value,
    };
  if (body.content !== $("content").value) {
    status(
      "이전 메시지의 저장 여부부터 확인하세요. 원래 내용으로 다시 확인할 수 있습니다.",
    );
    return;
  }
  outbox.set(room, body);
  $("send").disabled = true;
  status("DB 저장 확인 중…");
  let confirmed = false;
  try {
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        const result = await (
          await api(`/api/rooms/${target}/messages`, body)
        ).json();
        if (version === generation) {
          add([result]);
          $("content").value = "";
          status("DB 저장 완료");
        }
        outbox.delete(target);
        confirmed = true;
        break;
      } catch (e) {
        if (e.status && e.status !== 503) throw e;
        if (attempt === 4) throw e;
        if (version === generation)
          status("저장 결과 확인 중 · 같은 요청 ID로 재확인");
        await new Promise((ok) => setTimeout(ok, 2000));
      }
    }
  } catch (e) {
    status("전송 미확정: " + e.message + " · 내용과 요청을 확인하세요.");
  } finally {
    $("send").disabled = false;
    if (!confirmed)
      console.info("Message acknowledgement unverified; no success claim.");
  }
};
$("file").onchange = async () => {
  const file = $("file").files[0];
  if (!file || !room) return;
  if (file.size > 1048576) {
    status("첨부는 1MB 이하로 제한합니다.");
    return;
  }
  const target = room,
    id = crypto.randomUUID();
  try {
    await api(`/api/rooms/${target}/attachments/${id}`, undefined, {
      method: "PUT",
      headers: {
        "X-Consultation-CSRF": proof,
        "Content-Type": "application/octet-stream",
        "X-Filename-Encoded": encodeURIComponent(file.name),
      },
      body: await file.arrayBuffer(),
    });
    const b = document.createElement("button");
    b.textContent = file.name + " 다운로드";
    b.onclick = async () => {
      try {
        const response = await api(`/api/rooms/${target}/attachments/${id}`);
        const blob = await response.blob(),
          url = URL.createObjectURL(blob),
          a = document.createElement("a");
        a.href = url;
        a.download = file.name;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      } catch (e) {
        status(e.message);
      }
    };
    $("attachment").append(b);
    status("첨부 저장·메타데이터 확인 완료");
  } catch (e) {
    status("첨부 저장 미확정: " + e.message);
  }
};
$("summary").onclick = async () => {
  if (!room) return;
  try {
    const result = await (await api(`/api/rooms/${room}/summary`, {})).json();
    $("summary-result").textContent = result.summary;
  } catch (e) {
    $("summary-result").textContent =
      e.message === "ai_gateway_unconfigured"
        ? "AI Gateway가 연결되지 않았습니다. 요약 결과를 임의로 생성하지 않습니다."
        : e.message;
  }
};
const initial = location.hash.slice(1);
history.replaceState(null, "", "/");
if (initial) void login(initial).catch((e) => status(e.message));
else if (proof)
  void load().catch(() => {
    sessionStorage.removeItem("consultation-proof");
    proof = "";
    status("세션을 확인할 수 없습니다. 새 초대코드가 필요합니다.");
  });
