const crypto = require('crypto');
const jwt = require('jsonwebtoken');

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;

  cookieHeader.split(';').forEach((entry) => {
    const [rawKey, ...rest] = entry.trim().split('=');
    if (!rawKey) return;
    cookies[rawKey] = decodeURIComponent(rest.join('=') || '');
  });

  return cookies;
}

async function getSignedInUser(req, res) {
  const userIdFromHeader = req.headers['x-user-id'];
  const emailFromHeader = req.headers['x-user-email'];

  if (userIdFromHeader) {
    return {
      id: String(userIdFromHeader),
      email: emailFromHeader ? String(emailFromHeader) : null,
      stripe_accounts: []
    };
  }

  const cookies = parseCookies(req.headers.cookie);
  let anonymousUserId = cookies.chatbase_user_id;

  if (!anonymousUserId) {
    anonymousUserId = `anon_${crypto.randomUUID()}`;
    const isSecure = req.headers['x-forwarded-proto'] === 'https';
    const securePart = isSecure ? '; Secure' : '';
    res.setHeader(
      'Set-Cookie',
      `chatbase_user_id=${encodeURIComponent(anonymousUserId)}; Path=/; HttpOnly${securePart}; SameSite=Lax; Max-Age=31536000`
    );
  }

  return {
    id: anonymousUserId,
    email: null,
    stripe_accounts: []
  };
}

module.exports = async function handler(req, res) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const secret = process.env.CHATBOT_IDENTITY_SECRET;
  if (!secret) {
    return res.status(500).json({ error: 'Missing CHATBOT_IDENTITY_SECRET environment variable' });
  }

  try {
    const user = await getSignedInUser(req, res);
    const token = jwt.sign(
      {
        user_id: user.id,
        email: user.email,
        stripe_accounts: user.stripe_accounts
      },
      secret,
      { expiresIn: '1h' }
    );

    return res.status(200).json({ token });
  } catch (error) {
    console.error('Failed to generate Chatbase identity token:', error);
    return res.status(500).json({ error: 'Failed to generate token' });
  }
};
