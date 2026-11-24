const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
app.disable('x-powered-by');          // ne pas divulguer le moteur (Express)
app.use(express.json());
app.use(express.urlencoded({ extended: false })); // formulaires HTML
const port = process.env.PORT || 8000;
// Mode debug coupe hors developpement : vrai uniquement si NODE_ENV=development.
const isDev = process.env.NODE_ENV === 'development';
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-only-insecure-secret';
const BCRYPT_ROUNDS = 12;             // cout du hachage (lent volontairement)

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

// Reponse d'erreur GENERIQUE (jamais de trace technique cote utilisateur).
// errorId relie la reponse de l'utilisateur au detail journalise cote serveur.
function respondError(req, res, status, message, errorId) {
  res.status(status);
  const wantsJson =
    (req.headers.accept || '').includes('application/json') ||
    req.path.startsWith('/api') || req.path === '/health';
  if (wantsJson) {
    res.json({ ok: false, error: message, ...(errorId ? { errorId } : {}) });
  } else {
    res.type('html').send(`<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Erreur - Rempart</title>
<style>body{font:16px system-ui,sans-serif;background:#0f1222;color:#e8e8f0;
display:grid;place-items:center;min-height:100vh;margin:0}.c{text-align:center;
padding:2rem;max-width:34rem}a{color:#ff9a62}</style></head>
<body><main class="c">
  <h1>Oups, une erreur est survenue</h1>
  <p>${escapeHtml(message)}</p>
  ${errorId ? `<p style="color:#8a90b5">Reference : ${escapeHtml(errorId)}</p>` : ''}
  <p><a href="/">Retour a l'accueil</a></p>
</main></body></html>`);
  }
}

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
    <p>Compte (inscription / connexion / deconnexion) :
       <a href="/account">/account</a></p>
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

// ========================================================================
//  AUTHENTIFICATION : inscription / connexion / deconnexion
//  - mot de passe hache avec bcrypt (lent + sel integre), jamais en clair
//  - session via cookie HttpOnly signe (HMAC), pas de mdp dans le cookie
// ========================================================================

// Signe un jeton de session : "userId.expiration.signature".
function signSession(userId) {
  const exp = Date.now() + 3600 * 1000; // 1 h
  const data = `${userId}.${exp}`;
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('hex');
  return `${data}.${sig}`;
}

// Verifie le jeton et renvoie l'userId, ou null.
function verifySession(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [userId, exp, sig] = parts;
  const expected = crypto
    .createHmac('sha256', SESSION_SECRET).update(`${userId}.${exp}`).digest('hex');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  if (Date.now() > Number(exp)) return null;
  return userId;
}

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((c) => {
    const i = c.indexOf('=');
    if (i > -1) out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
  });
  return out;
}

function wantsJson(req) {
  return (req.headers.accept || '').includes('application/json') ||
         (req.headers['content-type'] || '').includes('application/json');
}

// --- Inscription ----------------------------------------------------------
app.post('/register', async (req, res, next) => {
  const email = (req.body?.email || '').toString().trim();
  const password = (req.body?.password || '').toString();
  try {
    if (!email || password.length < 8) {
      return reply(req, res, 400, { ok: false, error: 'email requis, mot de passe >= 8 caracteres' });
    }
    // bcrypt : hachage lent, avec sel genere automatiquement et inclus au hash.
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    // On n'insere QUE le hash. Le mot de passe en clair n'est jamais stocke.
    const result = await pool.query(
      'INSERT INTO app_users (email, pass_hash) VALUES ($1, $2) RETURNING id',
      [email, hash]
    );
    // NB : on ne journalise jamais le mot de passe (ni req.body).
    console.log(`[register] nouvel utilisateur id=${result.rows[0].id}`);
    startSession(res, result.rows[0].id);
    return reply(req, res, 201, { ok: true, user: { id: result.rows[0].id, email } }, '/account');
  } catch (err) {
    if (err.code === '23505') { // email deja pris (contrainte unique)
      return reply(req, res, 409, { ok: false, error: 'email deja utilise' });
    }
    next(err);
  }
});

// --- Connexion ------------------------------------------------------------
app.post('/login', async (req, res, next) => {
  const email = (req.body?.email || '').toString().trim();
  const password = (req.body?.password || '').toString();
  try {
    // email = PARAMETRE $1 : "' OR '1'='1" reste une simple chaine, pas de bypass.
    const result = await pool.query(
      'SELECT id, email, pass_hash, role FROM app_users WHERE email = $1',
      [email]
    );
    const user = result.rows[0];
    // bcrypt.compare : rejoue le hash sur la saisie et compare, a temps constant.
    const okPass = user ? await bcrypt.compare(password, user.pass_hash) : false;
    if (!user || !okPass) {
      return reply(req, res, 401, { ok: false, error: 'identifiants invalides' });
    }
    startSession(res, user.id);
    return reply(req, res, 200,
      { ok: true, user: { id: user.id, email: user.email, role: user.role } }, '/account');
  } catch (err) {
    next(err);
  }
});

// --- Deconnexion ----------------------------------------------------------
app.post('/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  return reply(req, res, 200, { ok: true }, '/account');
});

// --- Qui suis-je (etat de session) ---------------------------------------
app.get('/me', async (req, res, next) => {
  const userId = verifySession(parseCookies(req).session);
  if (!userId) return res.status(401).json({ ok: false, error: 'non connecte' });
  try {
    const r = await pool.query('SELECT id, email, role FROM app_users WHERE id = $1', [userId]);
    if (!r.rows[0]) return res.status(401).json({ ok: false, error: 'non connecte' });
    res.json({ ok: true, user: r.rows[0] });
  } catch (err) { next(err); }
});

// --- Page compte (formulaires HTML) --------------------------------------
app.get('/account', async (req, res, next) => {
  const userId = verifySession(parseCookies(req).session);
  try {
    let who = null;
    if (userId) {
      const r = await pool.query('SELECT email FROM app_users WHERE id = $1', [userId]);
      who = r.rows[0]?.email || null;
    }
    const body = who
      ? `<p>Connecte en <strong>${escapeHtml(who)}</strong>.</p>
         <form method="post" action="/logout"><button>Se deconnecter</button></form>`
      : `<h2>Inscription</h2>
         <form method="post" action="/register">
           <input name="email" type="email" placeholder="email" required>
           <input name="password" type="password" placeholder="mot de passe (>= 8)" required>
           <button>S'inscrire</button>
         </form>
         <h2>Connexion</h2>
         <form method="post" action="/login">
           <input name="email" type="email" placeholder="email" required>
           <input name="password" type="password" placeholder="mot de passe" required>
           <button>Se connecter</button>
         </form>`;
    res.type('html').send(`<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Compte - Rempart</title>
<style>body{font:16px system-ui,sans-serif;background:#0f1222;color:#e8e8f0;
margin:0;padding:2rem}a{color:#ff9a62}input{display:block;margin:.3rem 0;padding:.4rem}
form{margin:.5rem 0 1.5rem}</style></head>
<body><p><a href="/">&larr; Accueil</a></p><h1>Compte</h1>${body}</body></html>`);
  } catch (err) { next(err); }
});

// Pose le cookie de session signe (HttpOnly : inaccessible au JavaScript).
function startSession(res, userId) {
  const token = signSession(userId);
  res.setHeader('Set-Cookie',
    `session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600`);
}

// Repond en JSON (API) ou par une redirection (formulaire HTML).
function reply(req, res, status, json, redirectTo) {
  if (wantsJson(req) || !redirectTo) return res.status(status).json(json);
  return res.redirect(303, redirectTo);
}

// Cree l'utilisateur de demo au demarrage (hash bcrypt calcule a l'execution).
async function ensureDemoUser() {
  const hash = await bcrypt.hash('Demo#1234', BCRYPT_ROUNDS);
  await pool.query(
    `INSERT INTO app_users (email, pass_hash, role) VALUES ($1, $2, 'admin')
     ON CONFLICT (email) DO NOTHING`,
    ['demo@rempart.local', hash]
  );
  console.log('[init] utilisateur de demo pret (demo@rempart.local)');
}

// 404 : page generique, pas de details sur ce qui existe ou non.
app.use((req, res) => {
  respondError(req, res, 404, 'Page introuvable.');
});

// Gestionnaire d'erreur GLOBAL (doit avoir 4 arguments).
// Le DETAIL (message + pile) est journalise cote serveur ; l'utilisateur ne
// recoit qu'un message neutre et une reference pour le support.
app.use((err, req, res, next) => {
  const errorId = crypto.randomBytes(6).toString('hex');
  // -> va dans les journaux du serveur, PAS dans la reponse.
  console.error(`[error ${errorId}]`, err.stack || err);

  if (res.headersSent) return next(err);
  const status = err.status || err.statusCode || 500;
  const safeStatus = status >= 400 && status < 500 ? status : 500;
  // Hors dev, message strictement generique. En dev seulement, on aide le
  // developpeur avec le message (jamais la pile) dans la reponse.
  const message = isDev
    ? `Une erreur est survenue : ${err.message}`
    : 'Une erreur est survenue. Reessayez plus tard.';
  respondError(req, res, safeStatus, message, errorId);
});

app.listen(port, () => {
  console.log(`Rempart app en ecoute sur http://localhost:${port}`);
  ensureDemoUser().catch((e) => console.error('[init] demo user:', e.message));
});
