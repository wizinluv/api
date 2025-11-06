import crypto from 'crypto';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ valid: false });
  }

  const { key } = req.body;
  const normalizedKey = key.trim().toUpperCase();
  const keyHash = crypto.createHash('sha256').update(normalizedKey).digest('hex');

  const response = await fetch(`${SUPABASE_URL}/rest/v1/license_keys?key_hash=eq.${keyHash}`, {
    method: 'GET',
    headers: {
      apikey: SUPABASE_KEY,
      Authorization: `Bearer ${SUPABASE_KEY}`
    }
  });

  const data = await response.json();
  const valid = data && data.length > 0 && data[0].is_active && !data[0].is_paused;
  
  res.json({ valid });
}
