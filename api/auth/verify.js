// api/auth/verify.js — GET ?token=... Looks up token, sets session cookie, redirects to /.

import { kv } from '../_kv.js';
import {
  userIdFromEmail,
  createSessionCookie,
  buildSessionSetCookie,
} from '../_auth.js';

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).send('Method not allowed');
  }

  const token = req.query?.token;
  if (!token || typeof token !== 'string' || !/^[a-f0-9]{32}$/.test(token)) {
    return res.status(400).send(htmlError('That link looks invalid. Please request a new one.'));
  }

  if (!process.env.AUTH_SECRET) {
    return res.status(503).send(htmlError('Authentication is not configured. Set AUTH_SECRET env var.'));
  }

  const tokenKey = `steddi:auth:token:${token}`;
  let tokenData = null;
  try {
    const raw = await kv.get(tokenKey);
    if (!raw) {
      return res.status(400).send(htmlError("This link has expired or already been used. Request a new one from Steddi."));
    }
    tokenData = typeof raw === 'string' ? JSON.parse(raw) : raw;
  } catch (err) {
    console.error('[auth/verify] kv.get failed:', err?.message);
    return res.status(500).send(htmlError('Could not verify the link. Try again in a moment.'));
  }

  // Single-use: delete the token immediately
  try { await kv.del(tokenKey); } catch {}

  const email = String(tokenData?.email || '').trim().toLowerCase();
  const userId = userIdFromEmail(email);
  if (!userId) {
    return res.status(400).send(htmlError('The email on this link is invalid.'));
  }

  let cookieValue;
  try {
    cookieValue = createSessionCookie({ userId, email });
  } catch (err) {
    console.error('[auth/verify] cookie creation failed:', err?.message);
    return res.status(500).send(htmlError('Could not start your session. Try again.'));
  }

  res.setHeader('Set-Cookie', buildSessionSetCookie(cookieValue));
  res.setHeader('Cache-Control', 'no-store');
  // Redirect to root with a flag so the app knows it just signed in
  res.statusCode = 302;
  res.setHeader('Location', '/?signedin=1');
  res.end();
}

function htmlError(message) {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Steddi — Sign in</title>
  <style>
    body { font-family: -apple-system, system-ui, Helvetica, Arial, sans-serif; background: #FBF7F2; color: #1A1612; margin: 0; padding: 32px 16px; min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; box-sizing: border-box; }
    .card { background: white; max-width: 440px; width: 100%; border-radius: 20px; padding: 32px; box-shadow: 0 4px 24px rgba(0,0,0,0.08); text-align: center; }
    .emoji { font-size: 40px; margin-bottom: 8px; }
    h1 { font-family: Georgia, serif; font-weight: 400; font-size: 22px; margin: 0 0 12px; }
    p { color: #6A5A4E; font-size: 14px; line-height: 1.6; margin: 0 0 24px; }
    a.btn { display: inline-block; background: #E07840; color: white; text-decoration: none; padding: 12px 28px; border-radius: 50px; font-size: 14px; font-weight: 700; }
  </style>
</head>
<body>
  <div class="card">
    <div class="emoji">🐬</div>
    <h1>Sign-in didn't go through</h1>
    <p>${message}</p>
    <a class="btn" href="/">Open Steddi →</a>
  </div>
</body>
</html>`;
}
