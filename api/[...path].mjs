import { Pool } from 'pg';
import { handleRequest } from '../functions/nafis-api-core.mjs';

// Vercel Node Function adapter. DATABASE_URL and all credentials stay server-side.
let pool;
function getPool(env) {
  if (!env.DATABASE_URL) throw new Error('database_not_configured');
  pool ||= new Pool({ connectionString: env.DATABASE_URL, max: 5, idleTimeoutMillis: 30_000 });
  return pool;
}

function makeRequest(req, url) {
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers || {})) {
    if (Array.isArray(value)) value.forEach(v => headers.append(key, v));
    else if (value !== undefined) headers.set(key, String(value));
  }
  const body = ['GET', 'HEAD'].includes(req.method) ? undefined
    : typeof req.body === 'string' ? req.body : JSON.stringify(req.body ?? {});
  return new Request(url, { method: req.method, headers, ...(body === undefined ? {} : { body }) });
}

export function createApiHandler({ env = process.env, dbPool } = {}) {
  return async (req, res) => {
    const incoming = new URL(req.url || '/', `https://${req.headers?.host || 'localhost'}`);
    const apiPath = incoming.pathname.replace(/^\/api(?=\/|$)/, '') || '/';
    // Scheduled publishing has its own authenticated, non-public route.
    if (apiPath === '/internal/publish-results') {
      res.statusCode = 404;
      return res.end();
    }
    incoming.pathname = apiPath;
    try {
      const response = await handleRequest(makeRequest(req, incoming), { pool: dbPool || getPool(env), env });
      res.statusCode = response.status;
      response.headers.forEach((value, key) => res.setHeader(key, value));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch (error) {
      console.error('nafis_vercel_adapter_error', { name: error?.name || 'Error', code: error?.code || 'unknown' });
      res.statusCode = 503;
      res.setHeader('content-type', 'application/json; charset=utf-8');
      res.setHeader('cache-control', 'no-store');
      res.end(JSON.stringify({ error: 'server_unavailable', message: 'الخدمة غير جاهزة حاليًا.' }));
    }
  };
}

export default createApiHandler();
