import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { test } from 'node:test';
import assert from 'node:assert/strict';

async function browser() {
  const source = await readFile(new URL('./app.js', import.meta.url), 'utf8');
  const sockets = [], timers = [], elements = new Map();
  class Socket {
    close() { this.closed = true; this.onclose?.(); }
    constructor() { sockets.push(this); }
  }
  const element = () => ({ children: [], replaceChildren() { this.children = []; }, append(...children) { this.children.push(...children); } });
  const context = vm.createContext({
    WebSocket: Socket, URL, TextEncoder,
    location: { href: 'http://127.0.0.1:8794/', protocol: 'http:', hash: '' },
    history: { replaceState() {} },
    sessionStorage: { getItem() { return null; } },
    document: { createElement: element, getElementById(id) { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); } },
    setTimeout(callback) { timers.push(callback); },
  });
  vm.runInContext(source, context);
  vm.runInContext('room="test-room";proof="synthetic-proof";', context);
  return { context, sockets, timers, stream: () => vm.runInContext('stream()', context) };
}

test('late error/close from an old socket cannot close a replacement connection', async () => {
  const b = await browser();
  b.stream();
  const oldError = b.sockets[0].onerror, oldClose = b.sockets[0].onclose;
  b.stream();
  oldError(); oldClose();
  assert.equal(b.sockets.length, 2);
  assert.equal(b.sockets[1].closed, undefined);
  assert.equal(b.timers.length, 0);
});

test('a pending reconnect cannot replace an already restored connection', async () => {
  const b = await browser();
  b.stream(); b.sockets[0].close();
  assert.equal(b.timers.length, 1);
  b.stream(); b.timers[0]();
  assert.equal(b.sockets.length, 2);
  assert.equal(b.sockets[1].closed, undefined);
});


test('adjacent PostgreSQL BIGINT values remain distinct and sort exactly', async () => {
  const b = await browser();
  const rows = ['9007199254740993','9007199254740992'].map(sequence => ({ id: sequence, sequence, content: sequence, environment: 'test', writer_epoch: '1', created_at: '2026-11-02T00:00:00Z' }));
  vm.runInContext('add('+JSON.stringify(rows)+')', b.context);
  const ordered = vm.runInContext("document.getElementById('messages').children.map(li => li.children[0].textContent)",b.context);
  assert.deepEqual(Array.from(ordered),['9007199254740992','9007199254740993']);
});
