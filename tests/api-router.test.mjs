import test from 'node:test';
import assert from 'node:assert/strict';
import { createNestedApiRouter } from '../api/router.mjs';

test('nested API rewrite restores the full backend path and preserves caller query', async () => {
  let received;
  const route = createNestedApiRouter((req) => { received = req.url; });
  const req = {
    url: '/api/router?__nafis_path=admin/questions/12&view=full',
    headers: { host: 'preview.example' },
  };
  await route(req, {});
  assert.equal(received, '/api/admin/questions/12?view=full');
});

test('nested API rewrite accepts Vercel query values and retains the endpoint method', async () => {
  let observed;
  const route = createNestedApiRouter((req) => { observed = { url: req.url, method: req.method }; });
  const req = {
    url: '/api/router?keep=1',
    method: 'POST',
    headers: { host: 'preview.example' },
    query: { __nafis_path: 'auth/login' },
  };
  await route(req, {});
  assert.deepEqual(observed, { url: '/api/auth/login?keep=1', method: 'POST' });
});
