const crypto = require('crypto');
const express = require('express');
const { Pool } = require('pg');

const app = express();
app.use(express.json());
const port = process.env.PORT || 8000;

// Connexion a la base via une variable d'environnement.
// L'app se connecte avec un compte au MOINDRE PRIVILEGE (lecture seule),
// pas avec le superutilisateur de la base.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Page de garde
app.get('/', (req, res) => {
  res.type('html').send(`<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Rempart - Forteresse</title>
  <style>
    body { font: 16px system-ui, sans-serif; background: #0f1222; color: #e8e8f0;
           display: grid; place-items: center; min-height: 100vh; margin: 0; }
    .card { text-align: center; padding: 2rem; max-width: 36rem; }
    h1 { font-size: 2rem; margin: 0 0 .5rem; }
    a { color: #ff9a62; }
    code { background:#1b2040; padding:.1rem .3rem; border-radius:4px; }
  </style>
</head>
<body>
  <main class="card">
    <h1>Rempart est debout</h1>
    <p>Base : <a href="/health">/health</a></p>
    <p>Recherche (requete parametree) :
       <a href="/products?q=clavier">/products?q=clavier</a></p>
    <p>Login : <code>POST /login</code> { email, password }</p>
  </main>
</body>
</html>`);
});

// Sonde de sante : prouve que l'app parle a la base.
app.get('/health', async (req, res) => {
  try {
    const r = await pool.query('SELECT 1 AS ok');
    res.json({ status: 'ok', db: r.rows[0].ok === 1 ? 'up' : 'unknown' });
  } catch (err) {
    // Message generique cote client ; le detail reste dans les logs du serveur.
    console.error('[health]', err);
    res.status(503).json({ status: 'error', db: 'down' });
  }
});

// --- Recherche de produits : REQUETE PARAMETREE ---------------------------
// La donnee (q) ne touche jamais le texte de la requete : elle est passee
// SEPAREMENT, dans le tableau [ ... ], a la place du placeholder $1.
app.get('/products', async (req, res) => {
  const q = (req.query.q || '').toString();
  try {
    const result = await pool.query(
      'SELECT id, name, price FROM products WHERE name ILIKE $1 ORDER BY id',
      ['%' + q + '%']            // <-- la donnee voyage ici, pas dans le SQL
    );
    res.json({ query: q, count: result.rows.length, results: result.rows });
  } catch (err) {
    console.error('[products]', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

// --- Login : REQUETE PARAMETREE + verification du mot de passe en code -----
app.post('/login', async (req, res) => {
  const email = (req.body?.email || '').toString();
  const password = (req.body?.password || '').toString();
  try {
    // L'email est un PARAMETRE ($1). Meme "' OR '1'='1" est traite comme une
    // simple chaine a chercher : aucune ligne ne correspond, pas de bypass.
    const result = await pool.query(
      'SELECT id, email, pass_hash, role FROM app_users WHERE email = $1',
      [email]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ ok: false, error: 'identifiants invalides' });
    }
    const user = result.rows[0];
    if (!verifyPassword(password, user.pass_hash)) {
      return res.status(401).json({ ok: false, error: 'identifiants invalides' });
    }
    res.json({ ok: true, user: { id: user.id, email: user.email, role: user.role } });
  } catch (err) {
    console.error('[login]', err);
    res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

// Verifie un mot de passe contre un hash "salt:hash" (scrypt), a temps constant.
function verifyPassword(password, stored) {
  const [salt, hashHex] = String(stored).split(':');
  if (!salt || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = crypto.scryptSync(password, salt, expected.length);
  return expected.length === actual.length &&
         crypto.timingSafeEqual(expected, actual);
}

app.listen(port, () => {
  console.log(`Rempart app en ecoute sur http://localhost:${port}`);
});
