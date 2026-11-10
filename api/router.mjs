import { createApiHandler } from './[...path].mjs';

// Route nested API paths through a named Vercel function while preserving
// the path expected by the existing API handler.
export function createNestedApiRouter(handle) {
  return function route(req, res) {
    const url = new URL(req.url || '/', `https://${req.headers?.host || 'localhost'}`);
    const queryRoute = req.query?.__nafis_path;
    const routePath = Array.isArray(queryRoute)
      ? queryRoute.join('/')
      : queryRoute || url.searchParams.get('__nafis_path');

    if (typeof routePath === 'string' && routePath.trim()) {
      url.pathname = `/api/${routePath.replace(/^\/+/, '')}`;
      url.searchParams.delete('__nafis_path');
      req.url = `${url.pathname}${url.search}`;
    }

    return handle(req, res);
  };
}

export default createNestedApiRouter(createApiHandler());
