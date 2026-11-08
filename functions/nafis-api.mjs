import { Pool } from 'pg';
import { attachDatabasePool } from '@neon/functions';
import { handleRequest } from './nafis-api-core.mjs';

// Neon injects DATABASE_URL at runtime. It is never included in the browser bundle.
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 5, idleTimeoutMillis: 30_000 });
attachDatabasePool(pool);

export default {
  fetch(request) {
    return handleRequest(request, { pool, env: process.env });
  },
};
