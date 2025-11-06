import crypto from 'crypto';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ valid: false, error: 'Method not allowed' });
  }

  try {
    const { key } = req.body;

    if (!key || typeof key !== 'string') {
      return res.status(400).json({ valid: false, error: 'Invalid key format' });
    }

    const normalizedKey = key.trim().toUpperCase();

    if (!/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(normalizedKey)) {
      return res.status(400).json({ valid: false, error: 'Invalid key format' });
    }

    const keyHash = crypto.createHash('sha256').update(normalizedKey).digest('hex');

    const response = await fetch(
      `${SUPABASE_URL}/rest/v1/license_keys?key_hash=eq.${keyHash}&select=*`,
      {
        method: 'GET',
        headers: {
          'apikey': SUPABASE_KEY,
          'Authorization': `Bearer ${SUPABASE_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    const data = await response.json();

    if (!data || data.length === 0) {
      return res.status(200).json({ valid: false, error: 'Key not found' });
    }

    const keyData = data[0];

    if (!keyData.is_active) {
      return res.status(200).json({ valid: false, error: 'Key is revoked' });
    }

    if (keyData.is_paused) {
      return res.status(200).json({ valid: false, error: 'Key is paused' });
    }

    if (keyData.expiry_date) {
      const expiryDate = new Date(keyData.expiry_date);
      if (new Date() > expiryDate) {
        return res.status(200).json({ valid: false, error: 'Key expired' });
      }
    }

    if (keyData.max_uses && keyData.current_uses >= keyData.max_uses) {
      return res.status(200).json({ valid: false, error: 'Max uses exceeded' });
    }

    return res.status(200).json({ valid: true });

  } catch (error) {
    console.error('Validation error:', error.message);
    return res.status(500).json({ valid: false, error: 'Server error' });
  }
}
