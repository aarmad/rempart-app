// Tests de securite automatises, lances avec `node --test`.
// Ils envoient les charges d'attaque contre l'app en marche et verifient un
// RESULTAT PRECIS (pas seulement "ca n'a pas plante").
//
// Pre-requis : l'app tourne (docker compose up). URL configurable via BASE_URL.
const { test } = require('node:test');
const assert = require('node:assert/strict');

const BASE = process.env.BASE_URL || 'http://localhost:8000';

// --- 1) Injection SQL : la charge doit ressortir SAINE -------------------
test('injection SQL neutralisee sur /products', async () => {
  // Controle positif : une vraie recherche renvoie bien des resultats.
  const ok = await fetch(`${BASE}/products?q=clavier`).then((r) => r.json());
  assert.ok(ok.count >= 1, 'le controle positif doit renvoyer >= 1 resultat');

  // Attaque : ' OR '1'='1 ne doit PAS renvoyer toute la table.
  const payload = encodeURIComponent("' OR '1'='1");
  const res = await fetch(`${BASE}/products?q=${payload}`);
  const body = await res.json();

  assert.equal(res.status, 200);
  // La preuve que l'attaque a ECHOUE (et pas juste "pas plante") :
  // la charge est traitee comme un texte -> 0 resultat, et surtout
  // strictement moins que le controle positif (pas de fuite de lignes).
  assert.equal(body.count, 0, 'l injection ne doit renvoyer aucune ligne');
  assert.ok(body.count < ok.count, 'l injection ne doit pas renvoyer plus que la normale');
});

test('injection SQL neutralisee sur /login', async () => {
  const res = await fetch(`${BASE}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: "' OR '1'='1", password: 'x' }),
  });
  const body = await res.json();
  // Pas de bypass : refus explicite, pas une session admin.
  assert.equal(res.status, 401);
  assert.equal(body.ok, false);
});

// --- 2) XSS : la charge doit ressortir ECHAPPEE --------------------------
test('charge XSS ressort echappee sur /search', async () => {
  const raw = '<img src=x onerror=alert(1)>';
  const res = await fetch(`${BASE}/search?q=${encodeURIComponent(raw)}`);
  const html = await res.text();

  assert.equal(res.status, 200);
  // La preuve que l'attaque a ECHOUE : la version ECHAPPEE est presente...
  assert.ok(
    html.includes('&lt;img src=x onerror=alert(1)&gt;'),
    'la charge doit apparaitre echappee'
  );
  // ...et la balise BRUTE executable est absente de la reponse.
  assert.ok(
    !html.includes(raw),
    'la balise <img ...> brute ne doit jamais apparaitre telle quelle'
  );
});

// --- 3) Upload : un fichier interdit doit etre REFUSE --------------------
test('upload interdit refuse (.php deguise en .jpg)', async () => {
  // Controle positif : un vrai PNG est accepte (l endpoint fonctionne).
  const pngBytes = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
    'base64'
  );
  const okForm = new FormData();
  okForm.append('file', new Blob([pngBytes], { type: 'image/png' }), 'real.png');
  const okRes = await fetch(`${BASE}/upload`, { method: 'POST', body: okForm });
  const okBody = await okRes.json();
  assert.equal(okRes.status, 200, 'un vrai PNG doit etre accepte');
  assert.equal(okBody.ok, true);

  // Attaque : un script PHP renomme .jpg, annonce image/jpeg.
  const evil = new FormData();
  evil.append(
    'file',
    new Blob([Buffer.from('<?php echo 1; ?>')], { type: 'image/jpeg' }),
    'evil.jpg'
  );
  const res = await fetch(`${BASE}/upload`, { method: 'POST', body: evil });
  const body = await res.json();

  // La preuve que l'attaque a ECHOUE : refus explicite 415, pas un 200.
  assert.equal(res.status, 415, 'le fichier interdit doit etre refuse (415)');
  assert.equal(body.ok, false);
});

// --- 4) Connexion discrete : meme message, pas d'enumeration -------------
test('message identique pour e-mail inconnu et mauvais mot de passe', async () => {
  const unknown = await fetch(`${BASE}/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'personne@nulle-part.local', password: 'x1234567890' }),
  });
  const wrong = await fetch(`${BASE}/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'demo@rempart.local', password: 'mauvais-mdp' }),
  });
  const a = await unknown.json();
  const b = await wrong.json();
  // Meme statut ET meme message : impossible de savoir si l'e-mail existe.
  assert.equal(unknown.status, 401);
  assert.equal(wrong.status, 401);
  assert.equal(a.error, b.error, 'le message doit etre identique dans les deux cas');
});

// --- 5) Connexion freinee : la limitation renvoie 429 -------------------
test('les tentatives sont limitees (429 apres plusieurs echecs)', async () => {
  const email = `brute-${Date.now()}@test.local`; // compte frais, compteur a 0
  let last = 0;
  for (let i = 0; i < 6; i++) {
    const r = await fetch(`${BASE}/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'faux' }),
    });
    last = r.status;
  }
  // La preuve que le brute-force est freine : la derniere tentative est bloquee.
  assert.equal(last, 429, 'apres le quota, la connexion doit renvoyer 429');
});

// --- 6) Controle d'acces par role (cote serveur) ------------------------
test('route admin : 403 pour un simple utilisateur, 200 pour un admin', async () => {
  // Simple utilisateur (role 'user' par defaut) : l'inscription ouvre une session.
  const email = `u-${Date.now()}@test.local`;
  const reg = await fetch(`${BASE}/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: 'motdepasse1234' }),
  });
  const userCookie = (reg.headers.get('set-cookie') || '').split(';')[0];
  const asUser = await fetch(`${BASE}/admin`, { headers: { Cookie: userCookie } });
  assert.equal(asUser.status, 403, 'un simple utilisateur doit etre refuse (403)');

  // Admin (compte de demo) : acces autorise.
  const login = await fetch(`${BASE}/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'demo@rempart.local', password: 'Demo#1234' }),
  });
  const adminCookie = (login.headers.get('set-cookie') || '').split(';')[0];
  const asAdmin = await fetch(`${BASE}/admin`, { headers: { Cookie: adminCookie } });
  assert.equal(asAdmin.status, 200, 'un admin doit etre autorise (200)');
});
