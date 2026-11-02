'use strict';
const button=document.getElementById('request'),result=document.getElementById('result'),proof=document.getElementById('proof');
async function invoke(){button.disabled=true;try{const response=await fetch('/api/workload',{headers:{'X-Sova-CSRF':JSON.parse(localStorage.getItem('sova_operator_proof')||'{}').token||''},cache:'no-store',signal:AbortSignal.timeout(6000)}),data=await response.json();result.textContent=response.ok&&data.proof?.ok?'실제 '+data.proof.target.toUpperCase()+' 응답 확인':'현재 응답 미확인';proof.textContent=JSON.stringify(data,null,2);}catch(error){result.textContent='연결 미확인';proof.textContent='성공으로 판단하지 않습니다.';}finally{button.disabled=false;}}
button.addEventListener('click',invoke);invoke();
