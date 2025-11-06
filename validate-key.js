import crypto from 'crypto';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { key } = req.body;
  
  if (!key) {
    return res.status(400).json({ error: 'Key required' });
  }

  const keyHash = crypto.createHash('sha256').update(key).digest('hex');

  try {
    const response = await fetch(`${SUPABASE_URL}/rest/v1/license_keys?key_hash=eq.${keyHash}`, {
      method: 'GET',
      headers: {
        'apikey': SUPABASE_KEY,
        'Authorization': `Bearer ${SUPABASE_KEY}`,
        'Content-Type': 'application/json'
      }
    });

    const data = await response.json();

    if (!data || data.length === 0) {
      return res.status(401).json({ valid: false });
    }

    const keyData = data[0];

    if (!keyData.is_active || keyData.is_paused) {
      return res.status(401).json({ valid: false });
    }

    if (keyData.expiry_date && new Date() > new Date(keyData.expiry_date)) {
      return res.status(401).json({ valid: false });
    }

    return res.status(200).json({ valid: true });

  } catch (error) {
    return res.status(500).json({ error: 'Server error' });
  }
}
