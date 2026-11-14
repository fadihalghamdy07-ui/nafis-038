import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import {
  readToken, adminSessionCookie, clearAdminSessionCookie, sameOriginRequest,
  authAdmin, adminOnly, handleRequest, ADMIN_SESSION_TTL_SECONDS, encodePassword, verifyPassword, activeAdminPasswordHash,
  withPreviewTestSavepoint,
} from '../functions/nafis-api-core.mjs';

const secret = 'test-only-session-secret';
const email = 'preview-admin@example.invalid';
function makeToken(exp, cv = Date.now()) {
  const body = Buffer.from(JSON.stringify({ sub: email, role: 'admin', iat: 1, exp, cv })).toString('base64url');
  const signature = createHmac('sha256', secret).update(body).digest('base64url');
  return body + '.' + signature;
}

test('admin session TTL remains eight hours', () => {
  assert.equal(ADMIN_SESSION_TTL_SECONDS, 8 * 60 * 60);
});

test('signed token is accepted before expiry and rejected at expiry', () => {
  const token = makeToken(100);
  assert.equal(readToken(token, secret, 99_000)?.sub, email);
  assert.equal(readToken(token, secret, 100_000), null);
});

test('tampered token is rejected', () => {
  const token = makeToken(100);
  const [body, signature] = token.split('.');
  const altered = body + '.' + (signature[0] === 'A' ? 'B' : 'A') + signature.slice(1);
  assert.equal(readToken(altered, secret, 99_000), null);
});

test('admin cookie uses HttpOnly Secure SameSite Strict attributes', () => {
  const cookie = adminSessionCookie(makeToken(100));
  assert.match(cookie, /^__Host-naf038_admin_session=/);
  assert.match(cookie, /Path=\//);
  assert.match(cookie, /Max-Age=28800/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /Secure/);
  assert.match(cookie, /SameSite=Strict/);
});

test('logout clears the session cookie', () => {
  const cookie = clearAdminSessionCookie();
  assert.match(cookie, /^__Host-naf038_admin_session=;/);
  assert.match(cookie, /Max-Age=0/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /Secure/);
  assert.match(cookie, /SameSite=Strict/);
});

test('admin authorization accepts cookies and rejects bearer-only tokens', () => {
  const token = makeToken(Math.floor(Date.now() / 1000) + 3600);
  const env = { NAFIS_SESSION_SECRET: secret, NAFIS_ADMIN_EMAIL: email };
  const cookieRequest = new Request('https://preview.example/admin/bootstrap', {
    headers: { cookie: '__Host-naf038_admin_session=' + token },
  });
  const bearerRequest = new Request('https://preview.example/admin/bootstrap', {
    headers: { authorization: 'Bearer ' + token },
  });
  assert.equal(authAdmin(cookieRequest, env)?.sub, email);
  assert.equal(authAdmin(bearerRequest, env), null);
});

test('mutations accept only same-origin requests for CSRF defense', () => {
  assert.equal(sameOriginRequest(new Request('https://preview.example/admin/settings', {
    method: 'PATCH', headers: { origin: 'https://preview.example' },
  })), true);
  assert.equal(sameOriginRequest(new Request('https://preview.example/admin/settings', {
    method: 'PATCH', headers: { origin: 'https://attacker.example' },
  })), false);
  assert.equal(sameOriginRequest(new Request('https://preview.example/admin/settings', { method: 'PATCH' })), false);
});

test('password update and login verification share the same scrypt format and database source', async () => {
  const hash = await encodePassword('fake-isolated-test-password');
  assert.ok(hash.startsWith('scrypt' + String.fromCharCode(36)));
  assert.equal(await verifyPassword('fake-isolated-test-password', hash), true);
  assert.equal(await verifyPassword('different-test-password', hash), false);
  const dbPool = { query: async () => ({ rows: [{ password_hash: hash }] }) };
  assert.equal(await activeAdminPasswordHash(dbPool, 'environment-fallback'), hash);
  const emptyPool = { query: async () => ({ rows: [] }) };
  assert.equal(await activeAdminPasswordHash(emptyPool, 'environment-fallback'), 'environment-fallback');
});




function revocationPool(initialVersion) {
  const state = { version: initialVersion };
  return {
    state,
    async query(sql) {
      if (sql.startsWith('SELECT updated_at FROM public.naf038_admin_credentials')) {
        return { rows: [{ updated_at: new Date(state.version).toISOString() }] };
      }
      if (sql.startsWith('UPDATE public.naf038_admin_credentials')) {
        state.version += 2;
        return { rows: [{ updated_at: new Date(state.version).toISOString() }], rowCount: 1 };
      }
      throw new Error('Unexpected query in focused session test');
    },
  };
}
function adminEnv() {
  return { NAFIS_SESSION_SECRET: secret, NAFIS_ADMIN_EMAIL: email };
}
function cookieToken(response) {
  const value = response.headers.get('set-cookie') || '';
  return value.match(/__Host-naf038_admin_session=([^;]*)/)?.[1] || '';
}

test('revoke-others rotates the server version and keeps only the returned session valid', async () => {
  const initialVersion = Date.now() - 10000;
  const oldToken = makeToken(Math.floor(Date.now() / 1000) + 3600, initialVersion);
  const pool = revocationPool(initialVersion);
  const response = await handleRequest(new Request('https://preview.example/admin/sessions/revoke-others', {
    method: 'POST',
    headers: {
      origin: 'https://preview.example',
      cookie: '__Host-naf038_admin_session=' + oldToken,
      'content-type': 'application/json',
    },
  }), { pool, env: adminEnv() });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).revoked, true);
  const replacement = cookieToken(response);
  assert.ok(replacement);
  const current = authAdmin(new Request('https://preview.example/admin/bootstrap', {
    headers: { cookie: '__Host-naf038_admin_session=' + replacement },
  }), adminEnv());
  assert.ok(current);
  assert.equal(current.cv, pool.state.version);
  const oldResponse = await handleRequest(new Request('https://preview.example/admin/bootstrap', {
    headers: { cookie: '__Host-naf038_admin_session=' + oldToken },
  }), { pool, env: adminEnv() });
  assert.equal(oldResponse.status, 401);
  assert.equal((await oldResponse.json()).error, 'admin_session_revoked');
});

test('logout revokes the signed unexpired session on the server and clears its cookie', async () => {
  const initialVersion = Date.now() - 10000;
  const token = makeToken(Math.floor(Date.now() / 1000) + 3600, initialVersion);
  const pool = revocationPool(initialVersion);
  const response = await handleRequest(new Request('https://preview.example/auth/logout', {
    method: 'POST',
    headers: {
      origin: 'https://preview.example',
      cookie: '__Host-naf038_admin_session=' + token,
    },
  }), { pool, env: adminEnv() });
  assert.equal(response.status, 200);
  assert.match(response.headers.get('set-cookie') || '', /Max-Age=0/);
  const denied = await handleRequest(new Request('https://preview.example/admin/bootstrap', {
    headers: { cookie: '__Host-naf038_admin_session=' + token },
  }), { pool, env: adminEnv() });
  assert.equal(denied.status, 401);
  assert.equal((await denied.json()).error, 'admin_session_revoked');
});

test('revocation fails closed when the credential version cannot be read', async () => {
  const token = makeToken(Math.floor(Date.now() / 1000) + 3600);
  const request = new Request('https://preview.example/admin/bootstrap', {
    headers: { cookie: '__Host-naf038_admin_session=' + token },
  });
  const result = await adminOnly(request, adminEnv(), {
    query: async () => { throw new Error('database unavailable'); },
  });
  assert.ok(result instanceof Response);
  assert.equal(result.status, 503);
  assert.equal((await result.json()).error, 'admin_session_revocation_unavailable');
});

test('Preview runner rolls back only a rejected request savepoint and can continue its outer transaction', async () => {
  const snapshots = [];
  let aborted = false;
  const client = { async query(sql) {
    const command = String(sql).toUpperCase();
    if (command.startsWith('SAVEPOINT ')) { snapshots.push({ name: command.split(' ')[1], aborted }); return { rows: [] }; }
    if (command.startsWith('ROLLBACK TO SAVEPOINT ')) {
      const name = command.split(' ')[3];
      const snapshot = [...snapshots].reverse().find(item => item.name === name);
      if (!snapshot) throw new Error('missing savepoint');
      aborted = snapshot.aborted;
      return { rows: [] };
    }
    if (command.startsWith('RELEASE SAVEPOINT ')) { snapshots.pop(); return { rows: [] }; }
    if (command === 'SIMULATE UNIQUE CONSTRAINT') { aborted = true; throw Object.assign(new Error('duplicate'), { code: '23505' }); }
    if (command === 'SELECT 1') {
      if (aborted) throw Object.assign(new Error('transaction aborted'), { code: '25P02' });
      return { rows: [{ value: 1 }] };
    }
    throw new Error('Unexpected simulated query');
  } };
  const response = await withPreviewTestSavepoint(client, 'naf038_test_request_1', async () => {
    try { await client.query('SIMULATE UNIQUE CONSTRAINT'); }
    catch (error) { assert.equal(error.code, '23505'); return { status: 409 }; }
  });
  assert.equal(response.status, 409);
  assert.deepEqual((await client.query('SELECT 1')).rows, [{ value: 1 }]);
  assert.equal(snapshots.length, 0);
});
