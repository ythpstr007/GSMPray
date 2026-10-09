const keyCache = new Map();
export const privateHeaders = {
  'Content-Type': 'application/json',
  'Cache-Control': 'no-store, private',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'X-Robots-Tag': 'noindex, nofollow',
};
export function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: privateHeaders });
}
function decode(part) {
  if (!/^[A-Za-z0-9_-]+$/.test(part)) throw new Error('Invalid token');
  const raw = atob(part.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
function emails(value) {
  return new Set((value || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean));
}
export async function identity(request, env, fetchKeys = fetch) {
  const domain = env.ACCESS_TEAM_DOMAIN;
  const audience = env.ACCESS_AUD;
  const allowed = emails(env.ACCESS_ALLOWED_EMAILS);
  if (!domain || !/^[a-z0-9-]+\.cloudflareaccess\.com$/.test(domain) || !audience || !allowed.size) {
    throw new Error('Configuration unavailable');
  }
  const token = request.headers.get('Cf-Access-Jwt-Assertion');
  if (!token || token.length > 16384) throw new Error('Sign in required');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token');
  const header = JSON.parse(new TextDecoder().decode(decode(parts[0])));
  if (header.alg !== 'RS256' || typeof header.kid !== 'string') throw new Error('Invalid algorithm');
  let cached = keyCache.get(domain);
  if (!cached || cached.until < Date.now() || !cached.keys.some(k => k.kid === header.kid)) {
    const response = await fetchKeys(`https://${domain}/cdn-cgi/access/certs`, { redirect: 'error', signal: AbortSignal.timeout(5000) });
    if (!response.ok) throw new Error('Verification unavailable');
    const body = await response.json();
    if (!Array.isArray(body.keys)) throw new Error('Invalid signing keys');
    cached = { keys: body.keys, until: Date.now() + 3600000 };
    keyCache.set(domain, cached);
  }
  const jwk = cached.keys.find(k => k.kid === header.kid && k.kty === 'RSA');
  if (!jwk) throw new Error('Invalid signing key');
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, decode(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`))) throw new Error('Invalid signature');
  const claims = JSON.parse(new TextDecoder().decode(decode(parts[1])));
  const now = Math.floor(Date.now() / 1000);
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (claims.iss !== `https://${domain}` || !aud.includes(audience) || !Number.isFinite(claims.exp) || claims.exp <= now || !Number.isFinite(claims.iat) || claims.iat > now + 30 || (claims.nbf !== undefined && (!Number.isFinite(claims.nbf) || claims.nbf > now + 30)) || typeof claims.sub !== 'string' || typeof claims.email !== 'string') throw new Error('Invalid claims');
  const email = claims.email.toLowerCase();
  if (!allowed.has(email)) throw new Error('Access denied');
  return { email, isAdmin: emails(env.ACCESS_ADMIN_EMAILS).has(email) };
}
export async function readJson(request, limit = 1048576) {
  if (!request.headers.get('Content-Type')?.toLowerCase().startsWith('application/json')) throw new Error('Use JSON');
  if (Number(request.headers.get('Content-Length')) > limit) throw new Error('Body too large');
  if (!request.body) throw new Error('Missing body');
  const reader = request.body.getReader();
  let size = 0; const chunks = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) { await reader.cancel(); throw new Error('Body too large'); }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return JSON.parse(new TextDecoder().decode(bytes));
}
