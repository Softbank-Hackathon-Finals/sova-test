"use strict";
const $ = id => document.getElementById(id);
let current = null, cursor = null, auto = false, busy = false, switching = false, connected = false;
let selectedComponent="aws", selectedStep=null, workflowId=null, selectedWorkflow=null;
const seenRequests = new Set();
const names = {aws:"AWS",vm:"Linux VM"};
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
const clock = t => new Date(t*1000).toLocaleTimeString("ko-KR", {hour12:false});
function error(message) { $("error").hidden=!message; $("error").textContent=message; }
function expired(state) { return !state || state.now>=Date.parse(state.expires_at)/1000; }
function requestControls() {
  const unavailable=!connected||expired(current);
  $("send").disabled=unavailable||busy||switching;
  $("auto").disabled=unavailable||switching;
  if(unavailable){auto=false;$("auto").setAttribute("aria-checked","false");}
}
async function api(path,body) {
  const options=body===undefined?{cache:"no-store"}:{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)};
  const response=await fetch(path,{...options,signal:AbortSignal.timeout(7000)});
  const data=await response.json();
  if (!response.ok) throw new Error(data.error || "응답을 확인하지 못했습니다. 자동 재시도하지 않습니다.");
  return data;
}
function dot(side,ok) {
  if (!ok || reduced) return;
  const path=$(side+"Path"), length=path.getTotalLength();
  const node=document.createElementNS("http://www.w3.org/2000/svg","circle");
  node.setAttribute("r","4"); node.classList.add("particle"); $("particles").append(node);
  const start=performance.now();
  function frame(now) {
    const progress=Math.min((now-start)/900,1), point=path.getPointAtLength(progress*length);
    node.setAttribute("cx",point.x);node.setAttribute("cy",point.y);
    if(progress<1)requestAnimationFrame(frame);else node.remove();
  }
  requestAnimationFrame(frame);
}
function element(tag,text,cls) { const e=document.createElement(tag);e.textContent=text;if(cls)e.className=cls;return e; }
const kindNames={route_switch:"요청 경로 전환",security_drill:"통제 보안 시험 · 실제 SG 격리",security_restore:"시험 격리 해제"};
const statuses={pending:"대기",running:"실행 중",succeeded:"검증됨",failed:"실패",blocked:"진행 차단",needs_attention:"확인 필요"};
function renderPipeline(state){
  const history=state.workflows||[];
  const options=[element("option","실시간 · 최근 실행")];options[0].value="";
  for(const workflow of history){const option=element("option",clock(workflow.started_at)+" · "+(kindNames[workflow.kind]||workflow.kind));option.value=workflow.id;options.push(option);}
  $("workflowSelect").replaceChildren(...options);$("workflowSelect").value=selectedWorkflow||"";
  const op=history.find(w=>w.id===selectedWorkflow)||state.operation||state.last_operation;
  if(!op?.steps?.length)return;
  if(workflowId!==op.id){workflowId=op.id;selectedStep=null;}
  $("pipelineKind").textContent=(selectedWorkflow?"이력 · ":"")+(kindNames[op.kind]||"최근 실행");
  $("pipelineStatus").textContent=statuses[op.status]||op.status;
  $("pipelineStatus").classList.toggle("alert",op.status==="needs_attention");
  const selected=op.steps.find(s=>s.id===selectedStep)||op.steps.find(s=>s.status==="running"||s.status==="failed")||[...op.steps].reverse().find(s=>s.status==="succeeded")||op.steps[0];
  const nodes=[];
  op.steps.forEach((step,index)=>{
    if(index)nodes.push(element("span","→","pipeline-arrow"));
    const button=element("button","","pipeline-node "+step.status+(selected.id===step.id?" selected":""));
    button.setAttribute("aria-label",step.label+" · "+statuses[step.status]);button.setAttribute("aria-pressed",String(selected.id===step.id));button.dataset.step=step.id;
    const head=element("span","","step-head");head.append(element("span",{succeeded:"✓",failed:"×",running:"",pending:"",blocked:"−"}[step.status]||"","step-icon"),document.createTextNode(step.label));
    const elapsed=step.started_at?((step.completed_at||state.now)-step.started_at):null;
    button.append(head,element("span",step.status==="needs_attention"?"중단 · 결과 미확인":elapsed===null?statuses[step.status]:elapsed.toFixed(2)+"s · "+statuses[step.status],"step-time"));
    button.addEventListener("click",()=>{selectedStep=step.id;$("pipeline").classList.add("show-evidence");renderPipeline(current);});nodes.push(button);
  });
  $("pipelineGraph").replaceChildren(...nodes);
  $("stageTitle").textContent=selected.label+" · "+statuses[selected.status];
  $("stageTime").textContent=selected.started_at?"시작 "+clock(selected.started_at)+(selected.completed_at?" / 완료 "+clock(selected.completed_at):selected.status==="needs_attention"?" / 결과 미확인":" / 실행 중"):"앞선 단계가 완료되면 실행합니다.";
  $("stageEvidence").textContent=selected.evidence?JSON.stringify(selected.evidence,null,2):"실제 결과 대기 · 아직 성공으로 표시하지 않습니다.";
}
function renderComponents(state){
  const workload=state.workloads?.[selectedComponent];if(!workload)return;
  $("componentTitle").textContent="실행본 상세 · "+names[selectedComponent];
  $("componentBoundary").textContent=workload.boundary;
  const network=state.security?.network;
  const blocked=selectedComponent==="aws"&&network?.blocked&&state.now-network.observed_at<20;
  const nodes=[];
  workload.components.forEach((component,index)=>{
    if(index)nodes.push(element("span",index===1&&blocked?"×":"→","component-arrow"));
    nodes.push(element("span",component.label+(index===0&&blocked?" · 유입 차단":""),"component-box"+(index===0&&blocked?" blocked":"")));
  });
  $("componentGraph").replaceChildren(...nodes);
  $("componentFacts").replaceChildren(...[workload.runtime,"비루트 / 읽기 전용","DB 없음","code "+workload.revision.slice(0,10)].map(v=>element("span",v)));
}
function renderSecurity(state){
  const security=state.security||{state:"normal"},network=security.network;
  const fresh=network&&state.now-network.observed_at<20;
  const isolated=fresh&&network.blocked&&security.probe_blocked;
  $("awsNode").classList.toggle("isolated",!!isolated);
  $("awsGhost").setAttribute("visibility",isolated?"visible":"hidden");
  $("awsPath").classList.toggle("cut",!!(fresh&&network.blocked));
  if(isolated){$("awsNode").classList.remove("healthy","serving","unknown");$("awsState").textContent="● TCP8443 유입 격리 · 태스크 보존";$("awsPath").classList.remove("active");}
  $("quarantineCaption").textContent=!fresh?"격리 여부 미확인 · 최신 관측 대기":isolated?"AWS 실행본 유입 격리 확인":network.blocked?"유입 규칙 차단 · 연결 거부 확인 중":"격리된 실행본 없음";
  $("networkReadback").textContent=!fresh?"보안 그룹 최신 상태 미확인":network.blocked?"실제 SG: 수신 규칙 없음":"실제 SG: 등록된 경로만 허용";
  $("securityBadge").textContent=!fresh&&!state.operation?"보안 상태 미확인":{normal:"정상",investigating:"시험 조사",isolating:"격리 중",isolated:"유입 격리",needs_attention:"확인 필요"}[security.state]||"미확인";
  $("securityBadge").classList.toggle("security-badge-alert",security.state!=="normal");
  const inactive=expired(state),op=!!state.operation;
  $("securityDrill").disabled=switching||op||inactive||!fresh||security.state!=="normal"||!state.observations.aws?.available||state.observations.aws?.stale||!state.observations.vm?.available||state.observations.vm?.stale;
  $("securityRestore").disabled=switching||op||inactive||!security.controlled_test||!["isolated","needs_attention"].includes(security.state);
  if(security.state!=="normal")$("switchAws").disabled=true;
}
function render(state) {
  current=state;connected=true;requestControls();
  $("connection").classList.remove("offline");$("connection").replaceChildren(element("i",""),document.createTextNode("실측 연결됨"));
  const active=state.observations[state.route],fresh=active?.available&&!active.stale;
  $("activeMetric").textContent=fresh?names[state.route]:"미확인";
  $("routeRevision").textContent="게이트웨이 revision "+state.route_revision+(fresh?" · 응답 확인":" · 경로 설정과 응답 상태 구분");
  $("rps").textContent=state.metrics.rps.toFixed(1);
  $("success").textContent=state.metrics.success_percent===null?"—":state.metrics.success_percent.toFixed(1)+"%";
  $("samples").textContent="최근 60초 "+state.metrics.sample_count+"건 · 상태 확인 요청 제외";
  $("latency").textContent=state.metrics.p95_ms===null?"—":Math.round(state.metrics.p95_ms);
  for(const side of ["aws","vm"]) {
    const observation=state.observations[side],healthy=observation?.available&&!observation.stale;
    $(side+"Node").classList.remove("healthy","unknown","serving");
    $(side+"Node").classList.add(!healthy?"unknown":side===state.route?"serving":"healthy");
    $(side+"State").textContent=!healthy?"응답 미확인":side===state.route?"● 요청 처리 중":"● 응답 확인 · 대기";
    $(side+"Path").classList.toggle("active",side===state.route&&healthy);
  }
  $("lastCheck").textContent="마지막 조회 "+clock(state.now)+" · 1초 갱신";
  const inactive=expired(state), op=state.operation;
  $("switchVm").disabled=switching||!!op||inactive||state.route==="vm"||!state.observations.vm?.available||state.observations.vm?.stale;
  $("switchAws").disabled=switching||!!op||inactive||state.route==="aws"||!state.observations.aws?.available||state.observations.aws?.stale;
  $("operationTitle").textContent=op?(kindNames[op.kind]||"경로 전환")+" 실행 중":inactive?"테스트 실행 시간이 만료됐습니다":state.last_operation?.status==="needs_attention"?"실행 결과 확인 필요":"현재 "+names[state.route]+" 경로 · "+(fresh?"응답 확인":"실제 응답 미확인");
  $("operationDetail").textContent="기존 앱을 이동시키지 않고 새 요청의 목적지를 바꿉니다. DB 이전 없음.";
  const rows=state.requests.slice(0,8).map(r=>{
    const tr=element("tr","");tr.append(element("td",r.id.slice(0,12)),element("td",names[r.environment]));
    const status=element("td","");status.append(element("span",r.ok?"검증됨":"미확인","ok-pill"+(r.ok?"":" bad-pill")));
    tr.append(status,element("td",Math.round(r.latency_ms)+" ms"));return tr;
  });
  if(rows.length)$("requestRows").replaceChildren(...rows);
  const events=state.events.slice(-8).reverse().map(event=>{
    const li=element("li","",["route_applied","verified"].includes(event.kind)?"highlight":"");
    li.append(element("time",clock(event.at)));const detail=element("div",event.detail);detail.append(element("b","#"+event.seq+" · "+names[event.environment]));li.append(detail);return li;
  });
  $("events").replaceChildren(...events);$("eventCount").textContent="순서 번호 "+(state.events.at(-1)?.seq||0);
  // New observed request receipts trigger visual pulses. First load never replays old traffic.
  if(cursor!==null)for(const request of [...state.requests].reverse())if(!seenRequests.has(request.id)&&state.now-request.at<5)dot(request.environment,request.ok);
  for(const request of state.requests)seenRequests.add(request.id);
  if(seenRequests.size>2000){seenRequests.clear();for(const request of state.requests)seenRequests.add(request.id);}
  cursor=state.events.at(-1)?.seq||0;
  renderSecurity(state);renderPipeline(state);renderComponents(state);
}
async function refresh(){
  try{render(await api("/api/state"));}catch(e){
    connected=false;requestControls();
    $("connection").classList.add("offline");$("connection").replaceChildren(element("i",""),document.createTextNode("연결 끊김 · 상태 미확인"));
    if(current){for(const side of ["aws","vm"]){$(side+"Node").classList.remove("serving","healthy");$(side+"Node").classList.add("unknown");$(side+"State").textContent="연결 끊김 · 미확인";$(side+"Path").classList.remove("active");}}
    $("awsNode").classList.remove("isolated");$("awsGhost").setAttribute("visibility","hidden");$("awsPath").classList.remove("cut");
    $("quarantineCaption").textContent="격리 여부 미확인 · 제어기 연결 끊김";
    $("operationTitle").textContent="현재 서비스 상태 미확인";
    $("operationDetail").textContent="화면의 실행 이력은 보존됩니다. 연결 복구 전 새 작업을 보내지 않습니다.";
    $("activeMetric").textContent="미확인";$("rps").textContent=$("success").textContent=$("latency").textContent="—";
    $("samples").textContent="관측 중단 · 이전 수치를 현재 상태로 표시하지 않습니다.";
    $("switchVm").disabled=$("switchAws").disabled=$("securityDrill").disabled=$("securityRestore").disabled=true;
    $("securityBadge").textContent="미확인";$("networkReadback").textContent="연결 끊김 · 보안 상태 미확인";
    auto=false;$("auto").setAttribute("aria-checked","false");
  }
}
async function send(automatic=false){
  if(busy||switching||!connected||expired(current))return;
  busy=true;$("send").disabled=true;error("");
  try{
    const result=await api("/api/action",{message:$("message").value,automatic});
    $("receiptTitle").textContent="응답이 도착했습니다";$("receiptMessage").textContent=result.receipt.message;
    $("receiptEnv").textContent=names[result.environment];$("receiptId").textContent=result.request_id.slice(0,12);$("receiptId").title=result.request_id;$("receiptTime").textContent=result.latency_ms+" ms";
    await refresh();
  }catch(e){error(e.message);$("receiptTitle").textContent="응답을 확인하지 못했습니다";if(!current?.operation?.kind?.startsWith("security")){auto=false;$("auto").setAttribute("aria-checked","false");}}
  finally{busy=false;requestControls();}
}
$("send").addEventListener("click",()=>send());
$("message").addEventListener("keydown",e=>{if(e.key==="Enter")send();});
$("auto").addEventListener("click",()=>{if($("auto").disabled)return;auto=!auto;$("auto").setAttribute("aria-checked",String(auto));if(auto)send(true);});
for(const [id,side] of [["switchVm","vm"],["switchAws","aws"]])$(id).addEventListener("click",async()=>{
  if(switching)return;switching=true;selectedWorkflow=null;$("switchVm").disabled=$("switchAws").disabled=true;error("");
  try{await api("/api/switch",{environment:side});await refresh();}catch(e){error(e.message);}finally{switching=false;requestControls();}
});
for(const side of ["aws","vm"]){
  const select=()=>{selectedComponent=side;if(current)renderComponents(current);};
  $(side+"Node").addEventListener("click",select);
  $(side+"Node").addEventListener("keydown",e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();select();}});
}
for(const [id,action] of [["securityDrill","drill"],["securityRestore","restore"]])$(id).addEventListener("click",async()=>{
  if(switching)return;switching=true;selectedWorkflow=null;error("");$("securityDrill").disabled=$("securityRestore").disabled=true;
  try{await api("/api/security-test",{action,confirm:true});await refresh();}catch(e){error(e.message);}finally{switching=false;requestControls();}
});
$("workflowSelect").addEventListener("change",()=>{selectedWorkflow=$("workflowSelect").value||null;selectedStep=null;if(current)renderPipeline(current);});
setInterval(()=>{if(auto&&!document.hidden)send(true);},1000);
let refreshing=false;setInterval(async()=>{if(refreshing)return;refreshing=true;try{await refresh();}finally{refreshing=false;}},1000);
document.addEventListener("visibilitychange",()=>{if(document.hidden){auto=false;$("auto").setAttribute("aria-checked","false");}});
requestControls();refresh();
