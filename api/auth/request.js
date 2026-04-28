// api/auth/request.js — POST {email}. Generates a magic-link token and emails it.

import { kv } from '../_kv.js';
import { isValidEmail, generateToken, AUTH_CONSTANTS } from '../_auth.js';

const ALLOWED_ORIGIN = '*';
const RATE_LIMIT_PER_HOUR = 5; // per email

function safeError(res, code, msg) {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  return res.status(code).json({ error: msg });
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return safeError(res, 405, 'Method not allowed');

  const RESEND_KEY = process.env.RESEND_API_KEY;
  if (!RESEND_KEY) return safeError(res, 503, 'Email service not configured');

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { return safeError(res, 400, 'Invalid JSON'); }
  }
  const email = String(body?.email || '').trim().toLowerCase();
  if (!isValidEmail(email)) return safeError(res, 400, 'Invalid email');

  // Rate limit per email — prevents abuse
  try {
    const rateKey = `steddi:auth:rate:${email}`;
    const count = await kv.incr(rateKey);
    if (count === 1) {
      // first request this hour — set TTL
      try { await kv.set(rateKey, '1', { ex: 3600 }); } catch {}
    }
    if (count > RATE_LIMIT_PER_HOUR) {
      return safeError(res, 429, 'Too many requests. Try again in an hour.');
    }
  } catch {
    // Rate limit failure shouldn't block the request — log only
  }

  const token = generateToken();
  const tokenKey = `steddi:auth:token:${token}`;

  try {
    await kv.set(tokenKey, JSON.stringify({ email, createdAt: Date.now() }), { ex: AUTH_CONSTANTS.TOKEN_TTL_SECONDS });
  } catch (err) {
    console.error('[auth/request] kv.set failed:', err?.message);
    return safeError(res, 500, 'Storage unavailable');
  }

  // Build the magic link
  const host = req.headers.host || 'steddi-olie.vercel.app';
  const proto = req.headers['x-forwarded-proto'] || 'https';
  const link = `${proto}://${host}/api/auth/verify?token=${token}`;

  const subject = 'Your Steddi sign-in link 🐬';
  const html = `
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#FBF7F2;font-family:'Helvetica Neue',Arial,sans-serif;">
  <div style="max-width:500px;margin:32px auto;background:white;border-radius:20px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
    <div style="background:#E07840;padding:28px 32px;text-align:center;">
      <div style="font-size:40px;margin-bottom:8px;">🐬</div>
      <div style="font-family:Georgia,serif;font-size:22px;color:white;">steddi</div>
    </div>
    <div style="padding:32px;text-align:center;">
      <h2 style="font-family:Georgia,serif;font-weight:400;color:#1A1612;font-size:20px;margin:0 0 12px;">Tap to sign in</h2>
      <p style="color:#6A5A4E;font-size:14px;line-height:1.6;margin:0 0 28px;">
        We got a request to sign in to Steddi. If that was you, tap the button below. The link is good for 15 minutes.
      </p>
      <a href="${link}" style="display:inline-block;background:#E07840;color:white;text-decoration:none;padding:14px 32px;border-radius:50px;font-size:15px;font-weight:700;">Sign in to Steddi →</a>
      <p style="color:#999;font-size:12px;line-height:1.6;margin:32px 0 0;">
        If you didn't ask for this, you can safely ignore this email. No one can sign in without tapping the link from your inbox.
      </p>
    </div>
  </div>
</body>
</html>`;
  const text = `Tap to sign in to Steddi: ${link}\n\nThis link expires in 15 minutes. If you didn't request this, ignore this email.`;

  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: 'Steddi <hello@steddi.app>',
        to: [email],
        subject,
        html,
        text,
      }),
    });
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      console.error('[auth/request] Resend error:', j);
      return safeError(res, 502, 'Email delivery failed');
    }
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('[auth/request] fetch error:', err?.message);
    return safeError(res, 500, 'Email service unavailable');
  }
}
