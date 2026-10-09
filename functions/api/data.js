import { json, readJson } from '../../shared/security.js';
const leaderFields = new Set(['prayedAt', 'prayedWeek', 'prayedWeekDate', 'prayCount', 'weekPrayCount', 'prayerRequests', 'updatedAt']);
function validPeople(people) {
  if (!Array.isArray(people) || people.length === 0 || people.length > 2000) return false;
  const ids = new Set();
  return people.every(p => {
    if (!p || typeof p !== 'object' || Array.isArray(p) || typeof p.id !== 'string' || p.id.length > 128 || ids.has(p.id) || typeof p.name !== 'string' || !p.name.trim() || p.name.length > 200) return false;
    ids.add(p.id);
    for (const k of ['updatedAt', 'prayedAt', 'prayedWeek', 'prayCount', 'weekPrayCount']) if (p[k] != null && (!Number.isFinite(p[k]) || p[k] < 0)) return false;
    for (const k of ['updatedAt', 'prayedAt', 'prayedWeek']) if (p[k] != null && p[k] > Date.now() + 60000) return false;
    if (p.prayedWeekDate != null && (typeof p.prayedWeekDate !== 'string' || p.prayedWeekDate.length > 32)) return false;
    if (p.prayerRequests != null && (!Array.isArray(p.prayerRequests) || p.prayerRequests.length > 100 || p.prayerRequests.some(s => typeof s !== 'string' || s.length > 4000))) return false;
    return true;
  });
}
export async function onRequest(context) {
  const { request, env, data } = context;
  if (!data.user) return json({ error: 'Sign in required' }, 401);
  if (!env.INTERCEDE_KV) return json({ error: 'Storage unavailable' }, 503);
  const key = new URL(request.url).searchParams.get('key') || 'people';
  if (!['people', 'settings'].includes(key)) return json({ error: 'Unknown resource' }, 400);
  if (key === 'settings') {
    if (request.method !== 'GET') return json({ error: 'Settings changes are disabled' }, 403);
    const raw = await env.INTERCEDE_KV.get('settings');
    const s = raw ? JSON.parse(raw) : {};
    // Never expose credentials or allow unauthenticated setup/reset.
    return json({ name: typeof s.name === 'string' ? s.name : 'Grace Student Ministry', sub: typeof s.sub === 'string' ? s.sub : '' });
  }
  if (request.method === 'GET') return json(JSON.parse(await env.INTERCEDE_KV.get('people') || '[]'));
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);
  let incoming, force;
  try {
    const parsed = await readJson(request);
    incoming = Array.isArray(parsed) ? parsed : parsed?.data;
    force = !Array.isArray(parsed) && parsed?.force === true;
    if (!validPeople(incoming)) throw new Error('Invalid roster');
  } catch { return json({ error: 'Invalid or oversized roster' }, 400); }
  if (force && !data.user.isAdmin) return json({ error: 'Admin access required' }, 403);
  const stored = JSON.parse(await env.INTERCEDE_KV.get('people') || '[]');
  if (!Array.isArray(stored)) return json({ error: 'Storage needs administrator attention' }, 503);
  const storedMap = new Map(stored.map(p => [p.id, p]));
  if (!data.user.isAdmin) {
    // Only mutable prayer fields may change. Never trust a client-side admin flag.
    for (const p of incoming) {
      const old = storedMap.get(p.id);
      if (!old) return json({ error: 'Admin access required to add people' }, 403);
      const protectedKeys = new Set([...Object.keys(old), ...Object.keys(p)].filter(k => !leaderFields.has(k)));
      for (const k of protectedKeys) if (JSON.stringify(old[k]) !== JSON.stringify(p[k])) return json({ error: 'Admin access required to edit student details' }, 403);
    }
  }
  const merged = incoming.map(p => {
    const old = storedMap.get(p.id);
    if (!old) return p;
    if ((p.updatedAt || 0) < (old.updatedAt || 0)) return old;
    if (data.user.isAdmin) return p;
    const result = { ...old };
    for (const k of leaderFields) if (Object.hasOwn(p, k)) result[k] = p[k];
    return result;
  });
  if (!force) {
    const incomingIds = new Set(incoming.map(p => p.id));
    for (const p of stored) if (!incomingIds.has(p.id)) merged.push(p);
  }
  await env.INTERCEDE_KV.put('people', JSON.stringify(merged));
  return json({ ok: true, count: merged.length });
}
