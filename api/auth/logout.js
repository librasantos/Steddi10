// api/auth/logout.js — POST. Clears the session cookie.

import { buildLogoutSetCookie } from '../_auth.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  res.setHeader('Set-Cookie', buildLogoutSetCookie());
  res.setHeader('Cache-Control', 'no-store');
  return res.status(200).json({ ok: true });
}
