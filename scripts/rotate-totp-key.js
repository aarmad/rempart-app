const { Pool } = require('pg');
const { createTotpCipher, rotateTotpSecret } = require('../lib/totp-crypto');

// La nouvelle clé est lue sur l'entrée standard pour éviter les arguments
// de commande et les variables persistantes dans le conteneur de rotation.
async function readNewKey() {
  let input = '';
  for await (const chunk of process.stdin.setEncoding('utf8')) {
    input += chunk;
    if (input.length > 128) throw new Error('Entrée trop longue.');
  }
  return input.trim();
}

async function rotate() {
  const previous = createTotpCipher(process.env.TOTP_ENC_KEY);
  const next = createTotpCipher(await readNewKey());
  if (previous.keyId === next.keyId) throw new Error('La nouvelle clé doit être différente.');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  try {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('LOCK TABLE user_totp IN SHARE ROW EXCLUSIVE MODE');
      const { rows } = await client.query('SELECT user_id, secret_enc FROM user_totp');
      let changed = 0;
      for (const row of rows) {
        const encrypted = rotateTotpSecret(row.secret_enc, previous, next);
        if (encrypted === row.secret_enc) continue;
        await client.query('UPDATE user_totp SET secret_enc = $1 WHERE user_id = $2', [encrypted, row.user_id]);
        changed++;
      }
      await client.query('COMMIT');
      console.log('Rotation validée : ' + changed + ' secret(s) rechiffré(s).');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  } finally {
    await pool.end();
  }
}

rotate().catch(() => {
  console.error('Rotation interrompue. Vérifier la connexion, les deux clés et l’intégrité des données.');
  process.exitCode = 1;
});
