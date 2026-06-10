const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const mysql = require('mysql2/promise');
const crypto = require('crypto');

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

app.get('/health', (req, res) => {
  res.json({ status: 'Server is running' });
});

app.post('/api/shares', async (req, res) => {
  try {
    const { encrypted, salt, iv, recipientEmail, accessPassword } = req.body;

    if (!encrypted || !salt || !iv || !recipientEmail || !accessPassword) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const shareId = crypto.randomBytes(16).toString('hex');
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    const accessPasswordHash = crypto
      .createHash('sha256')
      .update(accessPassword)
      .digest('hex');

    const query = `
      INSERT INTO shares 
      (share_id, encrypted_data, salt, iv, recipient_email, access_password_hash, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `;

    await pool.execute(query, [
      shareId,
      JSON.stringify(encrypted),
      JSON.stringify(salt),
      JSON.stringify(iv),
      recipientEmail.toLowerCase().trim(),
      accessPasswordHash,
      expiresAt,
    ]);

    res.json({
      shareId,
      expiresAt,
    });
  } catch (error) {
    console.error('Error creating share:', error);
    res.status(500).json({ error: 'Failed to create share' });
  }
});

app.post('/api/shares/:shareId', async (req, res) => {
  try {
    const { shareId } = req.params;
    const { recipientEmail, accessPassword } = req.body;

    if (!recipientEmail || !accessPassword) {
      return res.status(400).json({ error: 'Missing email or password' });
    }

    const accessPasswordHash = crypto
      .createHash('sha256')
      .update(accessPassword)
      .digest('hex');

    const [rows] = await pool.execute(
      'SELECT * FROM shares WHERE share_id = ? LIMIT 1',
      [shareId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Share not found or expired' });
    }

    const share = rows[0];

    if (new Date() > new Date(share.expires_at)) {
      await pool.execute('DELETE FROM shares WHERE share_id = ?', [shareId]);
      return res.status(404).json({ error: 'This share has expired' });
    }

    if (share.recipient_email !== recipientEmail.toLowerCase().trim()) {
      return res.status(403).json({ error: 'Invalid email address' });
    }

    if (share.access_password_hash !== accessPasswordHash) {
      return res.status(403).json({ error: 'Incorrect password' });
    }

    res.json({
      encrypted: JSON.parse(share.encrypted_data),
      salt: JSON.parse(share.salt),
      iv: JSON.parse(share.iv),
    });
  } catch (error) {
    console.error('Error retrieving share:', error);
    res.status(500).json({ error: 'Failed to retrieve share' });
  }
});

const cleanupExpiredShares = async () => {
  try {
    const [result] = await pool.execute(
      'DELETE FROM shares WHERE expires_at < NOW()'
    );
    console.log(`Cleaned up ${result.affectedRows} expired shares`);
  } catch (error) {
    console.error('Error cleaning up expired shares:', error);
  }
};

setInterval(cleanupExpiredShares, 5 * 60 * 1000);

app.listen(port, () => {
  console.log(`SecureShare API running on port ${port}`);
});