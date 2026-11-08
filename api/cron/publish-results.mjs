import { timingSafeEqual } from 'node:crypto';
import { Pool } from 'pg';
import { handleRequest } from '../../functions/nafis-api-core.mjs';

let pool;
function authorized(req, secret) {
  const supplied = req.headers?.authorization || '';
  const actual = Buffer.from(supplied);
  const expected = Buffer.from(`Bearer ${secret || ''}`);
  return Boolean(secret && actual.length === expected.length && timingSafeEqual(actual, expected));
}

export function createCronHandler({ env = process.env, dbPool, now = () => Date.now() } = {}) {
  return async (req, res) => {
    if (req.method !== 'GET') { res.statusCode = 405; return res.end(); }
    if (!authorized(req, env.CRON_SECRET)) { res.statusCode = 401; return res.end(); }

    const current = new Date(now());
    // Only allow the configured Saturday 18:00 KSA invocation window (15:00 UTC).
    if (current.getUTCDay() !== 6 || current.getUTCHours() !== 15 || current.getUTCMinutes() > 14) {
      res.statusCode = 403;
      return res.end(JSON.stringify({ error: 'outside_schedule_window' }));
    }
    const scheduled = new Date(current);
    scheduled.setUTCMinutes(0, 0, 0);
    const request = new Request('https://internal.invalid/internal/publish-results', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-neon-trigger-invocation-id': 'vercel-cron' },
      body: JSON.stringify({ data: { scheduled_at: scheduled.toISOString() } }),
    });
    try {
      pool ||= dbPool || new Pool({ connectionString: env.DATABASE_URL, max: 5, idleTimeoutMillis: 30_000 });
      const response = await handleRequest(request, { pool, env });
      res.statusCode = response.status;
      response.headers.forEach((value, key) => res.setHeader(key, value));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch (error) {
      console.error('nafis_vercel_cron_error', { name: error?.name || 'Error', code: error?.code || 'unknown' });
      res.statusCode = 503;
      res.setHeader('content-type', 'application/json; charset=utf-8');
      res.end(JSON.stringify({ error: 'publish_failed' }));
    }
  };
}

export default createCronHandler();
