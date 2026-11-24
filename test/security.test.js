// Tests de securite automatises, lances avec `node --test`.
// Ils envoient les charges d'attaque contre l'app en marche et verifient un
// RESULTAT PRECIS (pas seulement "ca n'a pas plante").
//
// Pre-requis : l'app tourne (docker compose up). URL configurable via BASE_URL.
const { test } = require('node:test');
const assert = require('node:assert/strict');

const BASE = process.env.BASE_URL || 'http://localhost:8000';

// Jeton CSRF (double-submit) : toute requete qui MODIFIE doit presenter le
// meme jeton en cookie ET en entete. On en fixe un pour les tests.
const CSRF = 'test-csrf-token';
function mut(opts = {}, extraCookie = '') {
  const cookie = ['csrf=' + CSRF, extraCookie].filter(Boolean).join('; ');
  return {
    ...opts,
    headers: { ...(opts.headers || {}), 'X-CSRF-Token': CSRF, Cookie: cookie },
  };
}
const firstCookie = (r) => (r.headers.get('set-cookie') || '').split(';')[0];

// --- 1) Injection SQL : la charge doit ressortir SAINE -------------------
test('injection SQL neutralisee sur /products', async () => {
  const ok = await fetch(`${BASE}/products?q=clavier`).then((r) => r.json());
  assert.ok(ok.count >= 1, 'le controle positif doit renvoyer >= 1 resultat');

  const payload = encodeURIComponent("' OR '1'='1");
  const res = await fetch(`${BASE}/products?q=${payload}`);
  const body = await res.json();

  assert.equal(res.status, 200);
  assert.equal(body.count, 0, 'l injection ne doit renvoyer aucune ligne');
  assert.ok(body.count < ok.count, 'l injection ne doit pas renvoyer plus que la normale');
});

test('injection SQL neutralisee sur /login', async () => {
  const res = await fetch(`${BASE}/login`, mut({
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: "' OR '1'='1", password: 'x' }),
  }));
  const body = await res.json();
  assert.equal(res.status, 401);
  assert.equal(body.ok, false);
});

// --- 2) XSS : la charge doit ressortir ECHAPPEE --------------------------
test('charge XSS ressort echappee sur /search', async () => {
  const raw = '<img src=x onerror=alert(1)>';
  const res = await fetch(`${BASE}/search?q=${encodeURIComponent(raw)}`);
  const html = await res.text();

  assert.equal(res.status, 200);
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'), 'la charge doit apparaitre echappee');
  assert.ok(!html.includes(raw), 'la balise <img ...> brute ne doit jamais apparaitre telle quelle');
});

// --- 3) Upload : un fichier interdit doit etre REFUSE --------------------
test('upload interdit refuse (.php deguise en .jpg)', async () => {
  const pngBytes = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
    'base64'
  );
  const okForm = new FormData();
  okForm.append('file', new Blob([pngBytes], { type: 'image/png' }), 'real.png');
  const okRes = await fetch(`${BASE}/upload`, mut({ method: 'POST', body: okForm }));
  const okBody = await okRes.json();
  assert.equal(okRes.status, 200, 'un vrai PNG doit etre accepte');
  assert.equal(okBody.ok, true);

  const evil = new FormData();
  evil.append('file', new Blob([Buffer.from('<?php echo 1; ?>')], { type: 'image/jpeg' }), 'evil.jpg');
  const res = await fetch(`${BASE}/upload`, mut({ method: 'POST', body: evil }));
  const body = await res.json();

  assert.equal(res.status, 415, 'le fichier interdit doit etre refuse (415)');
  assert.equal(body.ok, false);
});

// --- 4) Connexion discrete : meme message, pas d'enumeration -------------
test('message identique pour e-mail inconnu et mauvais mot de passe', async () => {
  const unknown = await fetch(`${BASE}/login`, mut({
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'personne@nulle-part.local', password: 'x1234567890' }),
  }));
  const wrong = await fetch(`${BASE}/login`, mut({
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'demo@rempart.local', password: 'mauvais-mdp' }),
  }));
  const a = await unknown.json();
  const b = await wrong.json();
  assert.equal(unknown.status, 401);
  assert.equal(wrong.status, 401);
  assert.equal(a.error, b.error, 'le message doit etre identique dans les deux cas');
});

// --- 5) Connexion freinee : la limitation renvoie 429 -------------------
test('les tentatives sont limitees (429 apres plusieurs echecs)', async () => {
  const email = `brute-${Date.now()}@test.local`;
  let last = 0;
  for (let i = 0; i < 6; i++) {
    const r = await fetch(`${BASE}/login`, mut({
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'faux' }),
    }));
    last = r.status;
  }
  assert.equal(last, 429, 'apres le quota, la connexion doit renvoyer 429');
});

// --- 6) Controle d'acces par role (cote serveur) ------------------------
test('route admin : 403 pour un simple utilisateur, 200 pour un admin', async () => {
  const email = `u-${Date.now()}@test.local`;
  const reg = await fetch(`${BASE}/register`, mut({
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: 'motdepasse1234' }),
  }));
  const userCookie = firstCookie(reg);
  const asUser = await fetch(`${BASE}/admin`, { headers: { Cookie: userCookie } });
  assert.equal(asUser.status, 403, 'un simple utilisateur doit etre refuse (403)');

  const login = await fetch(`${BASE}/login`, mut({
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'demo@rempart.local', password: 'Demo#1234' }),
  }));
  const adminCookie = firstCookie(login);
  const asAdmin = await fetch(`${BASE}/admin`, { headers: { Cookie: adminCookie } });
  assert.equal(asAdmin.status, 200, 'un admin doit etre autorise (200)');
});

// --- 7) Anti-IDOR : chaque ressource verifie son proprietaire -----------
test('la note d un utilisateur renvoie 403 a un autre, et pas de mass assignment', async () => {
  const mkUser = async (email) => {
    const r = await fetch(`${BASE}/register`, mut({
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'motdepasse1234' }),
    }));
    return firstCookie(r);
  };
  const alice = await mkUser(`alice-${Date.now()}@test.local`);
  const bob = await mkUser(`bob-${Date.now()}@test.local`);

  const created = await fetch(`${BASE}/notes`, mut({
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: 'secret d Alice', user_id: 999, role: 'admin' }),
  }, alice)).then((r) => r.json());
  assert.notEqual(created.note.user_id, 999, 'user_id du body doit etre ignore');
  const id = created.note.id;

  const bobRead = await fetch(`${BASE}/notes/${id}`, { headers: { Cookie: bob } });
  assert.equal(bobRead.status, 403, 'la ressource d un autre doit renvoyer 403');

  const aliceRead = await fetch(`${BASE}/notes/${id}`, { headers: { Cookie: alice } });
  assert.equal(aliceRead.status, 200, 'le proprietaire doit pouvoir lire (200)');
});

// --- 8) CSRF : une requete modifiante sans jeton est refusee ------------
test('CSRF : POST sans jeton -> 403, avec jeton -> passe la barriere', async () => {
  // Sans cookie csrf ni entete : la barriere CSRF refuse.
  const noTok = await fetch(`${BASE}/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'demo@rempart.local', password: 'Demo#1234' }),
  });
  assert.equal(noTok.status, 403, 'sans jeton CSRF -> 403');
  assert.match((await noTok.json()).error, /CSRF/i);

  // Avec jeton (cookie == entete) : la requete franchit la barriere CSRF.
  const withTok = await fetch(`${BASE}/login`, mut({
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'demo@rempart.local', password: 'Demo#1234' }),
  }));
  assert.notEqual(withTok.status, 403, 'avec jeton CSRF -> pas de blocage CSRF');
});
