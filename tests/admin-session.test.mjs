import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import {
  readToken, adminSessionCookie, clearAdminSessionCookie, sameOriginRequest,
  authAdmin, ADMIN_SESSION_TTL_SECONDS,
} from '../functions/nafis-api-core.mjs';

const secret = 'test-only-session-secret';
const email = 'preview-admin@example.invalid';
function makeToken(exp) {
  const body = Buffer.from(JSON.stringify({ sub: email, role: 'admin', iat: 1, exp })).toString('base64url');
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
  assert.equal(readToken(token + 'x', secret, 99_000), null);
});

test('admin cookie uses host-only HttpOnly Secure SameSite Strict attributes', () => {
  const cookie = adminSessionCookie(makeToken(100));
  assert.match(cookie, /^__Host-naf038_admin_session=/);
  assert.match(cookie, /Path=\//);
  assert.match(cookie, /Max-Age=28800/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /Secure/);
  assert.match(cookie, /SameSite=Strict/);
});

test('expired session cookie is cleared on logout', () => {
  const cookie = clearAdminSessionCookie();
  assert.match(cookie, /^__Host-naf038_admin_session=;/);
  assert.match(cookie, /Max-Age=0/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /Secure/);
  assert.match(cookie, /SameSite=Strict/);
});

test('admin authorization accepts cookie and rejects bearer-only tokens', () => {
  const token = makeToken(Math.floor(Date.now() / 1000) + 3600);
  const env = { NAFIS_SESSION_SECRET: secret, NAFIS_ADMIN_EMAIL: email };
  const cookieRequest = new Request('https://preview.example/api/admin/bootstrap', {
    headers: { cookie: '__Host-naf038_admin_session=' + token },
  });
  const bearerRequest = new Request('https://preview.example/api/admin/bootstrap', {
    headers: { authorization: 'Bearer ' + token },
  });
  assert.equal(authAdmin(cookieRequest, env)?.sub, email);
  assert.equal(authAdmin(bearerRequest, env), null);
});

test('mutations accept only same-origin requests for CSRF defense', () => {
  assert.equal(sameOriginRequest(new Request('https://preview.example/api/admin/settings', {
    method: 'PATCH', headers: { origin: 'https://preview.example' },
  })), true);
  assert.equal(sameOriginRequest(new Request('https://preview.example/api/admin/settings', {
    method: 'PATCH', headers: { origin: 'https://attacker.example' },
  })), false);
  assert.equal(sameOriginRequest(new Request('https://preview.example/api/admin/settings', { method: 'PATCH' })), false);
});
