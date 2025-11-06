import crypto from 'crypto';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

export default async function handler(req, res) {
  // Allow POST only
  if (req.method !== 'POST') {
    return res.status(405).json({ valid: false, error: 'Method not allowed' });
  }

  try {
    const { key } = req.body;

    // Validate input
    if (!key || typeof key !== 'string') {
      return res.status(400).json({ valid: false, error: 'Invalid key format' });
    }

    // Normalize key (trim and uppercase for consistency)
    const normalizedKey = key.trim().toUpperCase();

    // Validate key format (should be like ABCD-EFGH-IJKL)
    if (!/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(normalizedKey)) {
      return res.status(400).json({ valid: false, error: 'Invalid key format' });
    }

    // Hash the key exactly like the Discord bot does
    const keyHash = crypto
      .createHash('sha256')
      .update(normalizedKey)
      .digest('hex');

    // Query Supabase for the key
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

    // Key not found
    if (!data || data.length === 0) {
      console.log(`Key not found in DB: ${normalizedKey}`);
      return res.status(200).json({ valid: false, error: 'Key not found' });
    }

    const keyData = data[0];
    console.log(`Key found: ${normalizedKey}, Active: ${keyData.is_active}, Paused: ${keyData.is_paused}`);

    // Check if key is active
    if (!keyData.is_active) {
      return res.status(200).json({ valid: false, error: 'Key is revoked' });
    }

    // Check if key is paused
    if (keyData.is_paused) {
      return res.status(200).json({ valid: false, error: 'Key is paused' });
    }

    // Check expiry date
    if (keyData.expiry_date) {
      const expiryDate = new Date(keyData.expiry_date);
      const now = new Date();
      if (now > expiryDate) {
        return res.status(200).json({ valid: false, error: 'Key expired' });
      }
    }

    // Check max uses
    if (keyData.max_uses && keyData.current_uses >= keyData.max_uses) {
      return res.status(200).json({ valid: false, error: 'Max uses exceeded' });
    }

    // Key is valid!
    return res.status(200).json({ valid: true });

  } catch (error) {
    console.error('Validation error:', error.message);
    return res.status(500).json({ valid: false, error: 'Server error' });
  }
}
