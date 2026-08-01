/**
 * The backend requires HTTP Basic Auth on /api/consult and /api/scan (see
 * backend/src/server.ts) so that another local process or user on a shared
 * host can't spend the operator's Anthropic quota or trigger scans for free.
 * Credentials are supplied via Vite env vars and must match the backend's
 * MCP_CONSULT_USER / MCP_CONSULT_PASSWORD.
 */
export function buildBackendHeaders(): Record<string, string> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const password = import.meta.env.VITE_CONSULT_PASSWORD;
  if (password) {
    const user = import.meta.env.VITE_CONSULT_USER || 'mcp-consult';
    headers['Authorization'] = `Basic ${btoa(`${user}:${password}`)}`;
  }
  return headers;
}

export const BACKEND_AUTH_HINT =
  "set VITE_CONSULT_PASSWORD in frontend/.env to match the backend's MCP_CONSULT_PASSWORD " +
  '(see the backend\'s startup log), then restart the dev server.';
