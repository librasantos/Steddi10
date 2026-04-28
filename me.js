// api/auth/me.js — GET. Returns the current user's session, or 401 if not signed in.

import { getSessionFromRequest } from '../_auth.js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const session = getSessionFromRequest(req);
  if (!session) return res.status(401).json({ ok: false, signedIn: false });

  return res.status(200).json({
    ok: true,
    signedIn: true,
    user: {
      userId: session.userId,
      email: session.email,
    },
  });
}
