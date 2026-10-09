import { identity, json, privateHeaders } from '../../shared/security.js';
export async function onRequest(context) {
  const { request, env } = context;
  if (!['GET', 'POST'].includes(request.method)) return json({ error: 'Method not allowed' }, 405);
  if (request.headers.get('Sec-Fetch-Site') === 'cross-site') return json({ error: 'Cross-site request blocked' }, 403);
  if (request.method === 'POST') {
    if (request.headers.get('Origin') !== new URL(request.url).origin || request.headers.get('X-GSM-Request') !== '1') return json({ error: 'Invalid request origin' }, 403);
  }
  try { context.data.user = await identity(request, env); }
  catch { return json({ error: 'Sign in with an approved leader account' }, 401); }
  const response = await context.next();
  const protectedResponse = new Response(response.body, response);
  for (const [key, value] of Object.entries(privateHeaders)) protectedResponse.headers.set(key, value);
  protectedResponse.headers.delete('Access-Control-Allow-Origin');
  return protectedResponse;
}
