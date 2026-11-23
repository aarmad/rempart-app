const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const multer = require('multer');
const { Pool } = require('pg');

const app = express();
app.use(express.json());
const port = process.env.PORT || 8000;

// --- Upload verrouille : configuration ------------------------------------
// Les fichiers sont stockes HORS du dossier public : aucune route statique ne
// sert ce dossier, seul /files/:id (controle) y donne acces.
const UPLOAD_DIR = path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const MAX_UPLOAD = 2 * 1024 * 1024; // taille maximale : 2 Mo
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD, files: 1 },
});

// Liste blanche : on identifie le type par le CONTENU (magic bytes),
// pas par l'extension ni le type MIME declare par le client.
const ALLOWED_TYPES = [
  { type: 'image/jpeg', ext: 'jpg',
    sniff: (b) => b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  { type: 'image/png', ext: 'png',
    sniff: (b) => b.length > 8 && b[0] === 0x89 && b[1] === 0x50 &&
                  b[2] === 0x4e && b[3] === 0x47 },
];

// Content-Security-Policy (bonus) : meme simple, elle bloque les scripts inline
// et les sources externes. script-src 'self' => un <script> injecte ou un
// onerror=... ne s'execute pas, en 2e barriere apres l'echappement.
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
  );
  next();
});

// Echappe une donnee pour l'inserer comme TEXTE dans du HTML.
// (equivalent d'un template qui echappe : < devient &lt;, etc.)
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

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
    <p>Recherche JSON (requete parametree) :
       <a href="/products?q=clavier">/products?q=clavier</a></p>
    <p>Recherche HTML (sortie echappee) :
       <a href="/search?q=clavier">/search?q=clavier</a></p>
    <p>Upload verrouille (JPEG/PNG only) : <a href="/upload">/upload</a></p>
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

// --- Page de resultats HTML : SORTIE ECHAPPEE -----------------------------
// La donnee utilisateur (q) et les noms de produits sont inseres via
// escapeHtml() : ils sortent en TEXTE, jamais interpretes comme du HTML.
app.get('/search', async (req, res) => {
  const q = (req.query.q || '').toString();
  try {
    const result = await pool.query(
      'SELECT id, name, price FROM products WHERE name ILIKE $1 ORDER BY id',
      ['%' + q + '%']
    );
    const items = result.rows
      .map((p) => `<li>${escapeHtml(p.name)} — ${escapeHtml(p.price)} EUR</li>`)
      .join('');
    res.type('html').send(`<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Recherche - Rempart</title>
  <style>
    body { font: 16px system-ui, sans-serif; background:#0f1222; color:#e8e8f0;
           margin:0; padding:2rem; }
    a { color:#ff9a62; } ul { line-height:1.8; }
    .echo { background:#1b2040; padding:.4rem .6rem; border-radius:6px; }
  </style>
</head>
<body>
  <p><a href="/">&larr; Accueil</a></p>
  <h1>Resultats de recherche</h1>
  <p>Vous avez cherche : <span class="echo">${escapeHtml(q)}</span></p>
  <ul>${items || '<li>Aucun resultat</li>'}</ul>
</body>
</html>`);
  } catch (err) {
    console.error('[search]', err);
    res.status(500).type('html').send('Erreur interne');
  }
});

// --- Upload verrouille : formulaire ---------------------------------------
app.get('/upload', (req, res) => {
  res.type('html').send(`<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Upload - Rempart</title>
<style>body{font:16px system-ui,sans-serif;background:#0f1222;color:#e8e8f0;
margin:0;padding:2rem}a{color:#ff9a62}</style></head>
<body>
  <p><a href="/">&larr; Accueil</a></p>
  <h1>Upload verrouille</h1>
  <p>Accepte uniquement JPEG / PNG (contenu verifie), max 2 Mo.</p>
  <form method="post" action="/upload" enctype="multipart/form-data">
    <input type="file" name="file" required>
    <button type="submit">Envoyer</button>
  </form>
</body></html>`);
});

// --- Upload verrouille : reception ----------------------------------------
app.post('/upload', (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ ok: false, error: 'fichier trop volumineux (max 2 Mo)' });
      }
      return res.status(400).json({ ok: false, error: 'upload invalide' });
    }
    if (!req.file) return res.status(400).json({ ok: false, error: 'aucun fichier' });

    // Verifier le CONTENU, pas l'extension ni le type declare par le client.
    const buf = req.file.buffer;
    const match = ALLOWED_TYPES.find((a) => a.sniff(buf));
    if (!match) {
      return res.status(415).json({
        ok: false,
        error: 'type refuse : seul un vrai JPEG ou PNG est accepte',
        recu: req.file.originalname,
      });
    }

    // Renommer : nom aleatoire + extension derivee du CONTENU verifie.
    const stored = crypto.randomBytes(16).toString('hex') + '.' + match.ext;
    fs.writeFileSync(path.join(UPLOAD_DIR, stored), buf);
    res.json({ ok: true, stored, type: match.type, url: '/files/' + stored });
  });
});

// --- Upload verrouille : telechargement sans danger -----------------------
app.get('/files/:id', (req, res) => {
  const id = req.params.id;
  // Nom strict (anti path traversal) : 32 hex + .jpg/.png, rien d'autre.
  if (!/^[a-f0-9]{32}\.(jpg|png)$/.test(id)) return res.status(400).end();
  const full = path.join(UPLOAD_DIR, id);
  if (!fs.existsSync(full)) return res.status(404).end();

  const type = id.endsWith('.png') ? 'image/png' : 'image/jpeg';
  res.setHeader('Content-Type', type);
  // nosniff : le navigateur ne "devine" pas un autre type que celui annonce.
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // attachment : le fichier est telecharge, jamais rendu/execute dans la page.
  res.setHeader('Content-Disposition', `attachment; filename="${id}"`);
  fs.createReadStream(full).pipe(res);
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
