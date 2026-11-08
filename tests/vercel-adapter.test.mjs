import test from 'node:test';
import assert from 'node:assert/strict';
import { createApiHandler } from '../api/[...path].mjs';
import { createCronHandler } from '../api/cron/publish-results.mjs';

function mockResponse() {
  return { headers: {}, statusCode: 200, body: '', setHeader(k, v) { this.headers[k] = v; }, end(v = '') { this.body = String(v); } };
}

test('Vercel API adapter responds to health through the same shared API core', async () => {
  const res = mockResponse();
  const handler = createApiHandler({ env: {}, dbPool: { query: async () => ({ rows: [{ ok: 1 }] }) } });
  await handler({ method: 'GET', url: '/api/health', headers: { host: 'api.test' } }, res);
  assert.equal(res.statusCode, 200);
  assert.deepEqual(JSON.parse(res.body), { ok: true });
  assert.equal(res.headers['cache-control'], 'no-store');
});

test('publishing route is not exposed by the general public API adapter', async () => {
  const res = mockResponse();
  const handler = createApiHandler({ env: {}, dbPool: { query: async () => { throw new Error('must not call DB'); } } });
  await handler({ method: 'POST', url: '/api/internal/publish-results', headers: { host: 'api.test' } }, res);
  assert.equal(res.statusCode, 404);
});

test('Vercel cron requires its secret and only publishes in the Saturday schedule window', async () => {
  let updates = 0;
  const pool = { async query(sql, params) {
    assert.match(sql, /UPDATE public\.naf038_settings/);
    assert.equal(params[1], '2026-W45');
    updates++;
    return { rows: [{ results_published_at: params[0] }] };
  } };
  const env = { CRON_SECRET: 'a-long-test-secret', DATABASE_URL: 'not-used-in-test' };
  const now = Date.parse('2026-11-07T15:02:00Z');
  const handler = createCronHandler({ env, dbPool: pool, now: () => now });
  const denied = mockResponse();
  await handler({ method: 'GET', headers: {} }, denied);
  assert.equal(denied.statusCode, 401);
  const outside = mockResponse();
  await createCronHandler({ env, dbPool: pool, now: () => Date.parse('2026-11-08T15:02:00Z') })({ method: 'GET', headers: { authorization: 'Bearer a-long-test-secret' } }, outside);
  assert.equal(outside.statusCode, 403);
  const accepted = mockResponse();
  await handler({ method: 'GET', headers: { authorization: 'Bearer a-long-test-secret' } }, accepted);
  assert.equal(accepted.statusCode, 200);
  assert.deepEqual(JSON.parse(accepted.body), { published: true, week: '2026-W45', results_published_at: '2026-11-07T15:00:00.000Z' });
  assert.equal(updates, 1);
});
