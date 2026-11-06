const express = require('express');
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 8000;

// La connexion a la base vient d'une variable d'environnement.
// Aucun secret n'est ecrit en dur dans le code.
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
    .card { text-align: center; padding: 2rem; }
    h1 { font-size: 2rem; margin: 0 0 .5rem; }
    a { color: #ff9a62; }
  </style>
</head>
<body>
  <main class="card">
    <h1>Rempart est debout</h1>
    <p>La forteresse repond. Verifie la base : <a href="/health">/health</a></p>
  </main>
</body>
</html>`);
});

// Sonde de sante : prouve que l'app parle vraiment a la base.
app.get('/health', async (req, res) => {
  try {
    const r = await pool.query('SELECT 1 AS ok');
    res.json({ status: 'ok', db: r.rows[0].ok === 1 ? 'up' : 'unknown' });
  } catch (err) {
    res.status(503).json({ status: 'error', db: 'down', message: err.message });
  }
});

app.listen(port, () => {
  console.log(`Rempart app en ecoute sur http://localhost:${port}`);
});
