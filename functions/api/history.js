import { json, readJson } from '../../shared/security.js';
export async function onRequest({ request, env, data }) {
  if (!data.user) return json({ error: 'Sign in required' }, 401);
  if (!env.INTERCEDE_KV) return json({ error: 'Storage unavailable' }, 503);
  if (request.method === 'GET') return json(JSON.parse(await env.INTERCEDE_KV.get('week_history') || '[]'));
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);
  if (!data.user.isAdmin) return json({ error: 'Admin access required' }, 403);
  let history;
  try {
    history = await readJson(request, 65536);
    if (!Array.isArray(history) || history.length > 52 || history.some(w => !w || typeof w !== 'object' || !Number.isFinite(w.weekStart) || !Number.isFinite(w.count) || w.count < 0 || !Number.isFinite(w.total) || w.total < 0)) throw new Error('Invalid history');
  } catch { return json({ error: 'Invalid history' }, 400); }
  await env.INTERCEDE_KV.put('week_history', JSON.stringify(history));
  return json({ ok: true });
}
