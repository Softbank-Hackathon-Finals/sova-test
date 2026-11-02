'use strict';
// Read only the fragment and clear it before making any network request.
// A user may paste the owner URL after already visiting this login page.
let exchanging = false;
function exchangeBootstrap() {
  const bootstrap = location.hash.slice(1);
  history.replaceState(null, '', '/');
  if (!bootstrap || exchanging) return;
  exchanging = true;
  const status = document.querySelector('#login-status');
  status.textContent = '운영자 확인 중…';
  fetch('/api/session', {method: 'POST', cache: 'no-store', credentials: 'same-origin',
    headers: {'Content-Type': 'application/json'}, body: JSON.stringify({bootstrap}),
    signal: AbortSignal.timeout(5000)})
    .then(async response => { if (!response.ok) throw Error('denied');
      const session = await response.json();
      localStorage.setItem('sova_operator_proof', JSON.stringify({token:session.origin_proof,expires_at:session.expires_at}));
      location.replace('/'); })
    .catch(() => { exchanging = false; status.textContent = '일회용 접속 정보가 만료되었거나 이미 사용되었습니다. 운영자에게 새 로컬 세션을 요청해 주세요.'; });
}
addEventListener('hashchange', exchangeBootstrap);
exchangeBootstrap();
