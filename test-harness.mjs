import { pathToFileURL } from 'node:url';
import { generateKeyPairSync, sign, webcrypto } from 'node:crypto';

const TEST = {
  from: '+10000000001',
  to: '+10000000002',
  text: 'TESTCODE 123456',
  botToken: 'PLACEHOLDER_BOT_TOKEN',
  chatId: 'PLACEHOLDER_CHAT_ID',
  discordWebhook: 'https://discord.example.test/webhooks/PLACEHOLDER',
};

const telegramUrl = `https://api.telegram.org/bot${TEST.botToken}/sendMessage`;
const expectedMessage = `SMS from ${TEST.from} to ${TEST.to}\n\n${TEST.text}`;

async function loadWorker(file) {
  const mod = await import(pathToFileURL(file).href);
  if (typeof mod.default?.fetch !== 'function') {
    throw new Error('worker ' + file + ' does not export a default fetch handler');
  }
  return mod.default.fetch;
}

function makeCtx(recorded) {
  return {
    waitUntil(p) { recorded.waits.push(p); },
    passThroughOnException() {},
  };
}

async function callWorker(handler, req, env) {
  const recorded = { fetches: [], waits: [] };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    recorded.fetches.push({
      url: String(url),
      body: init && init.body ? String(init.body) : '',
    });
    return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
  };
  try {
    const res = await handler(req, env, makeCtx(recorded));
    const out = { status: res.status, body: await res.text(), headers: Object.fromEntries(res.headers.entries()) };
    await Promise.all(recorded.waits);
    out.fetches = recorded.fetches;
    return out;
  } finally {
    globalThis.fetch = originalFetch;
  }
}

function findFetch(fetches, url) {
  return fetches.find((f) => f.url === url);
}

function telegramOk(fetch) {
  if (!fetch) return false;
  try {
    const body = JSON.parse(fetch.body);
    return body.chat_id === TEST.chatId && body.text === expectedMessage;
  } catch {
    return false;
  }
}

function discordOk(fetch) {
  if (!fetch) return false;
  try {
    const body = JSON.parse(fetch.body);
    return body.content === expectedMessage;
  } catch {
    return false;
  }
}

const bodyA = JSON.stringify({
  data: {
    event_type: 'message.received',
    payload: {
      from: { phone_number: TEST.from },
      to: [{ phone_number: TEST.to }],
      text: TEST.text,
    },
  },
});

const bodyC = JSON.stringify({ data: { event_type: 'message.delivered', payload: {} } });

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const rawPubB64 = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString('base64');
const ts = String(Math.floor(Date.now() / 1000));
const sig = sign(null, Buffer.from(ts + '|' + bodyA), privateKey);
const headersD = new Headers({
  'Content-Type': 'application/json',
  'telnyx-signature-ed25519': sig.toString('base64'),
  'telnyx-timestamp': ts,
});
const envD = {
  TELNYX_PUBLIC_KEY: rawPubB64,
  TELEGRAM_BOT_TOKEN: TEST.botToken,
  TELEGRAM_CHAT_ID: TEST.chatId,
  DISCORD_WEBHOOK_URL: TEST.discordWebhook,
};

const tsOld = String(Math.floor(Date.now() / 1000) - 600);
const sigOld = sign(null, Buffer.from(tsOld + '|' + bodyA), privateKey);
const headersE = new Headers({
  'Content-Type': 'application/json',
  'telnyx-signature-ed25519': sigOld.toString('base64'),
  'telnyx-timestamp': tsOld,
});

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
async function pbkdf2Hex(password, saltHex, iterations = 100000) {
  const enc = new TextEncoder();
  const keyMaterial = await webcrypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await webcrypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return bytesToHex(new Uint8Array(bits));
}

function createMockDB(initial = {}) {
  const state = {
    messages: Array.isArray(initial.messages) ? initial.messages.map(x => ({ ...x })) : [],
    users: Array.isArray(initial.users) ? initial.users.map(x => ({ ...x })) : [],
    sessions: Array.isArray(initial.sessions) ? initial.sessions.map(x => ({ ...x })) : [],
  };
  const calls = [];

  function matchWhere(row, sqlLower, args, kind) {
    // very small matcher tailored to queries used by worker
    if (kind === 'messages') {
      // INSERT handled separately. selects:
      // WHERE id = ?
      if (sqlLower.includes('from messages where id = ?')) {
        return row.id === args[0];
      }
      // list with optional filters and before cursor and q
      let ok = true;
      let ai = 0;
      if (sqlLower.includes('where')) {
        const wherePart = sqlLower.split('where')[1].split('order by')[0];
        if (wherePart.includes('body like ? or from_number like ? or to_number like ?')) {
          const like = args[ai++]; args[ai++]; args[ai++];
          const needle = String(like).slice(1, -1).toLowerCase();
          ok = ok && ((row.body||'').toLowerCase().includes(needle) || (row.from_number||'').toLowerCase().includes(needle) || (row.to_number||'').toLowerCase().includes(needle));
        }
        if (wherePart.includes('(created_at < ? or (created_at = ? and id < ?))')) {
          const c1 = args[ai++], c2 = args[ai++], idb = args[ai++];
          ok = ok && ((row.created_at < c1) || (row.created_at === c2 && String(row.id) < String(idb)));
        }
      }
      return ok;
    }
    if (kind === 'users') {
      if (sqlLower.includes('where email = ?')) return row.email === args[0];
      return true;
    }
    if (kind === 'sessions') {
      if (sqlLower.includes('where token_hash = ?')) return row.token_hash === args[0];
      return true;
    }
    return true;
  }

  function prepare(sql) {
    const record = { sql, binds: [] };
    calls.push(record);
    const api = {
      bind(...args) { record.binds = args; return api; },
      async run() {
        record.type = 'run';
        const s = sql.trim();
        const sl = s.toLowerCase();
        if (sl.startsWith('insert or ignore into messages')) {
          const [id, from_number, to_number, body, received_at, created_at] = record.binds;
          if (!state.messages.some(m => m.id === id)) {
            state.messages.push({ id, from_number, to_number, body, received_at, created_at });
            return { success: true, meta: { changes: 1 } };
          }
          return { success: true, meta: { changes: 0 } };
        }
        if (sl.startsWith('insert into sessions')) {
          const [token_hash, email, expires_at] = record.binds;
          state.sessions.push({ token_hash, email, expires_at });
          return { success: true, meta: { changes: 1 } };
        }
        if (sl.startsWith('insert into users')) {
          const [email, password_hash, salt, created_at] = record.binds;
          state.users.push({ email, password_hash, salt, failed_attempts: 0, locked_until: 0, created_at });
          return { success: true, meta: { changes: 1 } };
        }
        if (sl.startsWith('update users set failed_attempts')) {
          const [failed_attempts, locked_until, email] = record.binds;
          const u = state.users.find(u => u.email === email);
          if (u) { u.failed_attempts = failed_attempts; u.locked_until = locked_until; }
          return { success: true, meta: { changes: u ? 1 : 0 } };
        }
        if (sl.startsWith('update users set failed_attempts = 0')) {
          const [email] = record.binds;
          const u = state.users.find(u => u.email === email);
          if (u) { u.failed_attempts = 0; u.locked_until = 0; }
          return { success: true, meta: { changes: u ? 1 : 0 } };
        }
        if (sl.startsWith('delete from sessions')) {
          const [token_hash] = record.binds;
          const before = state.sessions.length;
          state.sessions = state.sessions.filter(s => s.token_hash !== token_hash);
          return { success: true, meta: { changes: before - state.sessions.length } };
        }
        throw new Error('mock run unsupported: ' + sql);
      },
      async all() {
        record.type = 'all';
        const s = sql.trim(); const sl = s.toLowerCase();
        if (sl.startsWith('select') && sl.includes(' from messages')) {
          let rows = state.messages.filter(r => matchWhere(r, sl, record.binds, 'messages'));
          if (sl.includes('order by created_at desc, id desc')) {
            rows = rows.slice().sort((a,b) => (b.created_at - a.created_at) || String(b.id).localeCompare(String(a.id)));
          }
          const limit = record.binds[record.binds.length - 1];
          if (sl.includes('limit ?') && Number.isFinite(limit)) rows = rows.slice(0, limit);
          return { results: rows };
        }
        throw new Error('mock all unsupported: ' + sql);
      },
      async first() {
        record.type = 'first';
        const s = sql.trim(); const sl = s.toLowerCase();
        if (sl.includes('from users')) {
          if (sl.includes('count(*)')) {
            return { c: state.users.length };
          }
          const rows = state.users.filter(r => matchWhere(r, sl, record.binds, 'users'));
          return rows[0] || null;
        }
        if (sl.includes('from sessions')) {
          const rows = state.sessions.filter(r => matchWhere(r, sl, record.binds, 'sessions'));
          return rows[0] || null;
        }
        if (sl.includes('from messages')) {
          if (sl.includes('count(*) as total')) return { total: state.messages.length };
          if (sl.includes('count(*) as today')) {
            const since = record.binds[0];
            const n = state.messages.filter(m => (m.created_at || 0) >= since).length;
            return { today: n };
          }
          const rows = state.messages.filter(r => matchWhere(r, sl, record.binds, 'messages'));
          return rows[0] || null;
        }
        throw new Error('mock first unsupported: ' + sql);
      },
    };
    return api;
  }

  return { prepare, _state: state, _calls: calls };
}

function getCookie(res, name) {
  const sc = res.headers['set-cookie'] || res.headers['Set-Cookie'] || '';
  const m = sc.match(new RegExp('(?:^|,\\s*)' + name + '=([^;]+)'));
  return m ? m[1] : null;
}

async function runOriginalForwardingTests(handler) {
  const results = {};

  let r = await callWorker(
    handler,
    new Request('https://relay.example/telnyx', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: bodyA }),
    {},
  );
  results.A = {
    pass: r.status === 200 && r.body === 'ok',
    detail: 'A no-env POST message.received -> ' + r.status + ' ' + JSON.stringify(r.body),
  };

  r = await callWorker(handler, new Request('https://relay.example/', { method: 'GET' }), {});
  results.B = {
    pass: r.status === 200 && r.body.includes('AI Stock VN SMS'),
    detail: 'B GET / -> ' + r.status + ' ' + JSON.stringify(r.body) + ' (expected placeholder per brief)',
  };

  r = await callWorker(
    handler,
    new Request('https://relay.example/telnyx', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: bodyC }),
    {},
  );
  results.C = {
    pass: r.status === 200 && r.body === 'ignored',
    detail: 'C other event type -> ' + r.status + ' ' + JSON.stringify(r.body),
  };

  r = await callWorker(
    handler,
    new Request('https://relay.example/telnyx', { method: 'POST', headers: headersD, body: bodyA }),
    envD,
  );
  const tg = findFetch(r.fetches, telegramUrl);
  const dc = findFetch(r.fetches, TEST.discordWebhook);
  const tgOk = telegramOk(tg);
  const dcOk = discordOk(dc);
  results.D = {
    pass: r.status === 200 && r.body === 'ok' && r.fetches.length === 2 && tgOk && dcOk,
    detail: 'D valid signature -> ' + r.status + ' ' + JSON.stringify(r.body)
      + '; fetch=' + JSON.stringify(r.fetches.map((f) => f.url))
      + '; telegram=' + tgOk + ' discord=' + dcOk,
  };

  r = await callWorker(
    handler,
    new Request('https://relay.example/telnyx', { method: 'POST', headers: headersE, body: bodyA }),
    envD,
  );
  results.E = {
    pass: r.status === 401 && r.body === 'invalid signature' && r.fetches.length === 0,
    detail: 'E stale timestamp -> ' + r.status + ' ' + JSON.stringify(r.body) + ' (expected 401)',
  };

  return results;
}

async function runDbAuthTests(handler) {
  const results = {};

  // webhook stores 1 row
  {
    const db = createMockDB();
    const body = JSON.stringify({
      data: { id: 'msg-1', event_type: 'message.received', payload: { from: { phone_number: '+1' }, to: [{ phone_number: '+2' }], text: 'hello', received_at: '2026-01-01T00:00:00Z' } },
    });
    const r = await callWorker(handler, new Request('https://relay.example/telnyx', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body }), { DB: db });
    results.store1 = {
      pass: r.status === 200 && db._state.messages.length === 1 && db._state.messages[0].id === 'msg-1' && db._state.messages[0].body === 'hello',
      detail: 'webhook stores 1 row -> status=' + r.status + ' messages=' + JSON.stringify(db._state.messages),
    };
  }

  // duplicate Telnyx id stores once
  {
    const db = createMockDB();
    const body = JSON.stringify({
      data: { id: 'msg-dup', event_type: 'message.received', payload: { from: '+1', to: '+2', text: 'hi' } },
    });
    const r1 = await callWorker(handler, new Request('https://relay.example/telnyx', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body }), { DB: db });
    const r2 = await callWorker(handler, new Request('https://relay.example/telnyx', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body }), { DB: db });
    results.dup = {
      pass: r1.status === 200 && r2.status === 200 && db._state.messages.length === 1,
      detail: 'duplicate Telnyx id stores once -> ' + r1.status + ',' + r2.status + ' count=' + db._state.messages.length,
    };
  }

  // non-message.received stores nothing
  {
    const db = createMockDB();
    const body = JSON.stringify({ data: { id: 'evt-2', event_type: 'message.delivered', payload: { text: 'x' } } });
    const r = await callWorker(handler, new Request('https://relay.example/telnyx', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body }), { DB: db });
    results.nonReceived = {
      pass: r.status === 200 && r.body === 'ignored' && db._state.messages.length === 0,
      detail: 'non-message.received stores nothing -> status=' + r.status + ' body=' + JSON.stringify(r.body) + ' count=' + db._state.messages.length,
    };
  }

  // /api/messages without cookie -> 401
  {
    const db = createMockDB();
    const r = await callWorker(handler, new Request('https://relay.example/api/messages', { method: 'GET' }), { DB: db });
    results.apiNoCookie = {
      pass: r.status === 401,
      detail: '/api/messages without cookie -> ' + r.status + ' ' + r.body,
    };
  }

  // login with correct PBKDF2 hash -> sets cookie + /api/auth/me 200
  {
    const salt = '00112233445566778899aabbccddeeff';
    const password = 'correcthorsebattery';
    const password_hash = await pbkdf2Hex(password, salt, 100000);
    const db = createMockDB({ users: [{ email: 'admin@aistockvn.com', password_hash, salt, failed_attempts: 0, locked_until: 0, created_at: 1 }] });
    const login = await callWorker(handler, new Request('https://relay.example/api/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@aistockvn.com', password }),
    }), { DB: db });
    const cookie = getCookie(login, 'session');
    const me = await callWorker(handler, new Request('https://relay.example/api/auth/me', {
      method: 'GET', headers: { 'Cookie': 'session=' + cookie },
    }), { DB: db });
    let meJson = null; try { meJson = JSON.parse(me.body); } catch {}
    results.loginOk = {
      pass: login.status === 200 && !!cookie && login.headers['set-cookie']?.includes('HttpOnly') && login.headers['set-cookie']?.includes('Secure') && login.headers['set-cookie']?.includes('SameSite=Lax') && me.status === 200 && meJson && meJson.email === 'admin@aistockvn.com',
      detail: 'login correct -> login=' + login.status + ' set-cookie=' + JSON.stringify(login.headers['set-cookie']) + ' me=' + me.status + ' ' + me.body,
    };
  }

  // wrong password -> 401
  {
    const salt = '00112233445566778899aabbccddeeff';
    const password_hash = await pbkdf2Hex('correcthorsebattery', salt, 100000);
    const db = createMockDB({ users: [{ email: 'admin@aistockvn.com', password_hash, salt, failed_attempts: 0, locked_until: 0, created_at: 1 }] });
    const login = await callWorker(handler, new Request('https://relay.example/api/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@aistockvn.com', password: 'wrongpassword!!' }),
    }), { DB: db });
    results.wrongPw = {
      pass: login.status === 401,
      detail: 'wrong password -> ' + login.status + ' ' + login.body,
    };
  }

  // 4th email -> rejected (register when users empty but email not in allowlist)
  {
    const db = createMockDB({ users: [] });
    const r = await callWorker(handler, new Request('https://relay.example/api/auth/register', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'someone@example.com', password: 'longenoughpassword' }),
    }), { DB: db });
    const okAllowed = await callWorker(handler, new Request('https://relay.example/api/auth/register', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@aistockvn.com', password: 'longenoughpassword' }),
    }), { DB: db });
    const r3 = await callWorker(handler, new Request('https://relay.example/api/auth/register', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'tranbinhanbr01@gmail.com', password: 'longenoughpassword' }),
    }), { DB: db });
    results.fourthEmail = {
      pass: r.status === 403 && okAllowed.status === 201 && r3.status === 403,
      detail: '4th/other email rejected; register only when empty -> other=' + r.status + ' allowedFirst=' + okAllowed.status + ' secondWhenNotEmpty=' + r3.status + ' body=' + r.body,
    };
  }

  // lockout after 5 fails
  {
    const salt = '00112233445566778899aabbccddeeff';
    const password_hash = await pbkdf2Hex('correcthorsebattery', salt, 100000);
    const db = createMockDB({ users: [{ email: 'admin@aistockvn.com', password_hash, salt, failed_attempts: 0, locked_until: 0, created_at: 1 }] });
    let last;
    for (let i = 0; i < 5; i++) {
      last = await callWorker(handler, new Request('https://relay.example/api/auth/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'admin@aistockvn.com', password: 'wrongpassword!!' }),
      }), { DB: db });
    }
    const after = await callWorker(handler, new Request('https://relay.example/api/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@aistockvn.com', password: 'correcthorsebattery' }),
    }), { DB: db });
    const user = db._state.users.find(u => u.email === 'admin@aistockvn.com');
    const now = Math.floor(Date.now()/1000);
    results.lockout = {
      pass: last.status === 401 && after.status === 401 && user && user.locked_until > now,
      detail: 'lockout after 5 fails -> 5th=' + last.status + ' correctAfterLock=' + after.status + ' locked_until=' + (user && user.locked_until) + ' now=' + now,
    };
  }

  // list ordering newest-first + q filter
  {
    const salt = '00112233445566778899aabbccddeeff';
    const password_hash = await pbkdf2Hex('correcthorsebattery', salt, 100000);
    const db = createMockDB({
      users: [{ email: 'admin@aistockvn.com', password_hash, salt, failed_attempts: 0, locked_until: 0, created_at: 1 }],
      messages: [
        { id: 'm1', from_number: '+1', to_number: '+2', body: 'alpha code', received_at: null, created_at: 100 },
        { id: 'm2', from_number: '+3', to_number: '+2', body: 'beta', received_at: null, created_at: 200 },
        { id: 'm3', from_number: '+4', to_number: '+2', body: 'alpha two', received_at: null, created_at: 150 },
      ],
    });
    const login = await callWorker(handler, new Request('https://relay.example/api/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@aistockvn.com', password: 'correcthorsebattery' }),
    }), { DB: db });
    const cookie = getCookie(login, 'session');
    const list = await callWorker(handler, new Request('https://relay.example/api/messages', {
      method: 'GET', headers: { 'Cookie': 'session=' + cookie },
    }), { DB: db });
    const filtered = await callWorker(handler, new Request('https://relay.example/api/messages?q=alpha', {
      method: 'GET', headers: { 'Cookie': 'session=' + cookie },
    }), { DB: db });
    let lj=null,fj=null; try{lj=JSON.parse(list.body);}catch{} try{fj=JSON.parse(filtered.body);}catch{}
    const order = lj && lj.messages ? lj.messages.map(m=>m.id).join(',') : '';
    const fq = fj && fj.messages ? fj.messages.map(m=>m.id).join(',') : '';
    results.list = {
      pass: list.status === 200 && order === 'm2,m3,m1' && filtered.status === 200 && fq === 'm3,m1',
      detail: 'list ordering + q -> order=' + order + ' filtered=' + fq + ' listBody=' + list.body + ' filteredBody=' + filtered.body,
    };
  }

  return results;
}

async function main() {
  const handler = await loadWorker('./worker.js');
  let allOk = true;

  console.log('== ORIGINAL FORWARDING TESTS (on new worker.js) ==');
  const orig = await runOriginalForwardingTests(handler);
  for (const k of ['A', 'B', 'C', 'D', 'E']) {
    console.log('worker.js ' + k + ': ' + orig[k].detail + ' => ' + (orig[k].pass ? 'PASS' : 'FAIL'));
    if (!orig[k].pass) allOk = false;
  }

  console.log('== DB/AUTH TESTS (mocked env.DB) ==');
  const ext = await runDbAuthTests(handler);
  for (const k of Object.keys(ext)) {
    console.log('ext ' + k + ': ' + ext[k].detail + ' => ' + (ext[k].pass ? 'PASS' : 'FAIL'));
    if (!ext[k].pass) allOk = false;
  }

  console.log('HARNESS RESULT: ' + (allOk ? 'ALL PASS' : 'FAIL'));
  process.exit(allOk ? 0 : 1);
}

main().catch(e => { console.error(e && e.stack || e); process.exit(1); });
