# Rempart

Squelette de la forteresse : une page de garde et une sonde `/health` reliee a
une base Postgres, le tout lance par Docker Compose en une commande.

## Stack

- Node.js + Express (serveur HTTP)
- PostgreSQL (base de donnees)
- Docker Compose (orchestration)

## Demarrage rapide

```bash
# 1. Preparer les secrets locaux
cp .env.example .env
# puis editer .env et mettre un vrai mot de passe

# 2. Construire et lancer
docker compose up --build

# 3. Verifier
#   Page de garde : http://localhost:8000
#   Sante + base  : http://localhost:8000/health
```

Arreter : `docker compose down` (ajouter `-v` pour supprimer aussi les donnees).

## Points de controle

| URL | Role |
| --- | --- |
| `GET /` | Page de garde |
| `GET /health` | Repond `{"status":"ok","db":"up"}` si la base repond ; `503` sinon |

## Variables d'environnement

| Variable | Role | Ou |
| --- | --- | --- |
| `POSTGRES_USER` | Utilisateur de la base | `.env` |
| `POSTGRES_PASSWORD` | Mot de passe de la base (**secret**) | `.env` |
| `POSTGRES_DB` | Nom de la base | `.env` |
| `DATABASE_URL` | Chaine de connexion, construite a partir des 3 ci-dessus | `docker-compose.yml` |
| `PORT` | Port d'ecoute de l'app (defaut 8000) | `docker-compose.yml` |

Le fichier `.env` contient les vrais secrets et **n'est jamais pousse** : il est
liste dans `.gitignore`. Seul `.env.example`, sans secret, est versionne.

## Le `.env` est-il bien ignore ?

```bash
# Si .env est ignore, git le liste comme ignore...
git check-ignore -v .env        # -> .gitignore:2:.env   .env

# ...et il n'apparait pas dans les fichiers suivis
git status --porcelain          # aucune ligne pour .env
git ls-files | grep .env        # ne montre que .env.example
```

### Et si un secret a deja ete pousse une fois ?

Le retirer d'un commit **ne suffit pas** : il reste dans l'historique git et
dans toute copie deja clonee (dont GitHub). Il faut considerer le secret comme
**compromis**. La marche a suivre :

1. **Changer le secret** (rotation) : regenerer le mot de passe / la cle cote
   service. C'est l'etape la plus importante : tant que la valeur est valide,
   l'effacer de l'historique ne protege de rien.
2. **Reparer le depot** : ajouter le fichier a `.gitignore`, puis
   `git rm --cached .env` et committer. Pour effacer la valeur de **tout**
   l'historique, reecrire l'historique avec `git filter-repo` (ou BFG
   Repo-Cleaner), puis `git push --force`.
3. **Prevenir** : garder les secrets hors du depot (`.env` ignore,
   `.env.example` sans valeur), et activer la detection de secrets (ex.
   protection de push / scan de secrets GitHub).

## Securite (carte des menaces)

Penser en attaquant avant d'ajouter des fonctionnalites : qui entre, par ou, et
ce qu'on protege.

### Schema des flux et frontieres de confiance

```
        === Frontiere : Internet | Hote ===
   Utilisateur / Attaquant
        |
        |  HTTP  (port 8000 publie)
        v
   +---------------------------------------------+
   |  Conteneur app  (Node / Express)            |
   |    GET /        -> page HTML                 |
   |    GET /health  -> requete SQL vers la base  |
   |    Secret : DATABASE_URL (variable d'env)    |
   +---------------------------------------------+
        |
        |  SQL  (reseau Compose, 5432 NON publie)
        v   === Frontiere : app | base ===
   +---------------------------------------------+
   |  Conteneur db  (PostgreSQL)                 |
   |    Donnees + identifiants                    |
   |    Volume dbdata (persistance)               |
   +---------------------------------------------+

   Autres frontieres de confiance :
     - Depot git / fichier .env   -> secrets (ne doivent pas sortir)
     - npm + images Docker        -> code tiers (chaine d'approvisionnement)
```

### Surfaces d'entree

| Surface | Detail |
| --- | --- |
| URL / routes HTTP | `GET /`, `GET /health` (port 8000) |
| Parametres de requete / corps | Pas encore utilises ; le deviendront des la 1re fonctionnalite |
| Cookies / sessions | Aucun pour l'instant (a prevoir avec l'authentification) |
| Fichiers | Aucun upload pour l'instant |
| API / variables d'env | `DATABASE_URL`, `PORT`, secrets du `.env` |
| Dependances | `express`, `pg` (npm) + images `node`, `postgres` (Docker) |
| Base de donnees | PostgreSQL, derriere la frontiere app/base |

### Cinq menaces classees (STRIDE), avec une premiere parade

| # | Menace | Categorie | Entre par | Parade (1re idee) |
| --- | --- | --- | --- | --- |
| 1 | **Injection SQL** : une entree utilisateur concatenee dans une requete expose toute la base | Tampering / Info disclosure | HTTP (port 8000) -> couche SQL | Requetes parametrees (placeholders `pg`), jamais de concatenation ; valider les entrees |
| 2 | **Fuite de secret** : `.env` pousse sur git ou inclus dans l'image -> identifiants de la base | Info disclosure / Elevation | Depot git / image Docker | `.env` ignore (fait), `.dockerignore` (fait), rotation si fuite, scan de secrets |
| 3 | **Dependance vulnerable** : CVE dans `express`/`pg` ou l'image de base -> RCE | Elevation of privilege | npm / Docker Hub | `npm audit`, epingler/mettre a jour les versions, images a jour |
| 4 | **Absence d'authentification / controle d'acces** : endpoints ouverts, pas d'autorisation | Spoofing / Elevation | Endpoints HTTP | Ajouter authn + authz avant toute donnee sensible ; refuser par defaut |
| 5 | **Deni de service** : requetes en masse, pool de connexions epuise | Denial of Service | HTTP (port 8000) | Limiter le debit (rate limit), timeouts, pool borne, reverse proxy |

> Note : la sonde `/health` renvoie aujourd'hui `err.message` en cas d'erreur,
> ce qui peut divulguer des details techniques (erreur bavarde). A durcir :
> message generique cote client, detail uniquement dans les logs.

### La menace la plus grave, et par ou elle entre

La plus grave est l'**injection SQL (#1)**. Elle entre par l'**interface HTTP
publique (port 8000)** : une valeur controlee par l'attaquant (parametre d'URL,
corps de requete) atteint la couche SQL. Si elle reussit, elle traverse la
frontiere app -> base et donne acces a **toutes** les donnees et identifiants,
voire a l'execution de commandes sur le serveur de base. C'est pour cela qu'elle
passe avant les autres : impact maximal (compromission totale) et surface
directement exposee a Internet.

## Requetes parametrees et moindre privilege (defense)

Parade directe de la menace #1 : la donnee utilisateur ne touche **jamais** le
texte de la requete SQL.

### Ou la donnee est-elle separee de la requete ?

Chaque requete utilise des **placeholders** (`$1`, `$2`, ...) et passe la donnee
**separement**, dans un tableau. Extrait de `server.js` (recherche de produits) :

```js
// server.js  -> GET /products
const result = await pool.query(
  'SELECT id, name, price FROM products WHERE name ILIKE $1 ORDER BY id',
  ['%' + q + '%']          // <-- la donnee voyage ICI, hors du texte SQL
);
```

Et pour le login :

```js
// server.js  -> POST /login
const result = await pool.query(
  'SELECT id, email, pass_hash, role FROM app_users WHERE email = $1',
  [email]                  // <-- "email" est une donnee, jamais du code
);
```

Le pilote `pg` envoie le texte de la requete et les valeurs par des canaux
distincts : une valeur ne peut pas devenir un mot-cle SQL. Le mot de passe, lui,
est verifie **en code** (scrypt a temps constant), pas dans une requete.

### Preuve : `' OR '1'='1` ne renvoie rien d'anormal

| Entree | Resultat |
| --- | --- |
| `GET /products?q=clavier` | 1 resultat (Clavier mecanique) |
| `GET /products?q=' OR '1'='1` | **0 resultat** : la charge est cherchee comme un simple texte |
| `POST /login` demo + bon mot de passe | `{"ok":true, role:"admin"}` |
| `POST /login` email = `' OR '1'='1` | `401 identifiants invalides` (aucun bypass) |

### Compte base au moindre privilege

L'app ne se connecte PAS avec le superutilisateur. Un role dedie `rempart_app`
est cree a l'init (`db/init/02-app-role.sh`) avec le strict minimum :

```sql
CREATE ROLE rempart_app LOGIN PASSWORD '***'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
GRANT CONNECT ON DATABASE rempart TO rempart_app;
GRANT USAGE ON SCHEMA public TO rempart_app;
GRANT SELECT ON products, app_users TO rempart_app;   -- lecture seule
```

Verifie :

| Action du role `rempart_app` | Resultat |
| --- | --- |
| Superutilisateur ? | **non** (`rolsuper = f`) |
| `SELECT` sur products | autorise |
| `INSERT` sur products | **refuse** (`permission denied`) |
| `DROP TABLE app_users` | **refuse** (`must be owner`) |

Ainsi, meme si une faille future laissait passer une requete malveillante, le
compte ne pourrait ni modifier ni detruire les donnees.

## Sortie echappee (defense XSS)

### Ou affiche-t-on une donnee utilisateur ?

Sur la page HTML `GET /search` : le terme recherche et les noms de produits y
sont affiches. Chaque valeur passe par `escapeHtml()` avant d'entrer dans le
HTML, donc elle sort en **TEXTE**, jamais interpretee comme des balises. Extrait
de `server.js` :

```js
res.type('html').send(`...
  <p>Vous avez cherche : <span class="echo">${escapeHtml(q)}</span></p>
  <ul>${items}</ul>  // items = ...map(p => `<li>${escapeHtml(p.name)}...`)
...`);

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
```

### Preuve : `<img src=x onerror=...>` s'affiche en toutes lettres

Requete : `GET /search?q=<img src=x onerror=alert(1)>`
Reponse (le HTML recu) :

```html
<span class="echo">&lt;img src=x onerror=alert(1)&gt;</span>
```

Les `<` et `>` sont devenus `&lt;` / `&gt;` : le navigateur affiche le texte
`<img src=x onerror=alert(1)>` au lieu de creer une balise. L'`onerror` ne
s'execute pas. (A comparer avec le DOM XSS de Juice Shop, ou la donnee entrait
via `innerHTML` sans echappement.)

### Du HTML riche est-il necessaire ? (DOMPurify)

Non. Toute donnee utilisateur de cette app est du **texte simple** (recherche,
email, avis). On l'**echappe**, c'est suffisant et plus sur. DOMPurify ne sert
que si on devait un jour accepter du HTML riche d'un utilisateur (ex. un editeur
WYSIWYG) : on passerait alors la valeur par `DOMPurify.sanitize(html)` avant
affichage, au lieu de l'echapper. Tant que ce besoin n'existe pas, on ne
l'introduit pas : moins de code, moins de surface.

### Content-Security-Policy (bonus)

Un en-tete CSP est pose sur toutes les reponses (`server.js`) comme 2e barriere :

```
Content-Security-Policy: default-src 'self'; script-src 'self';
  style-src 'self' 'unsafe-inline'; img-src 'self' data:;
  object-src 'none'; base-uri 'self'; frame-ancestors 'none'
```

`script-src 'self'` interdit les scripts inline et les gestionnaires d'evenement
(`onerror=...`) : meme si un HTML malveillant passait l'echappement, le
navigateur refuserait de l'executer.

## Upload verrouille (defense)

Endpoint `POST /upload` (formulaire sur `GET /upload`). Cinq verrous :

| Verrou | Mise en oeuvre (`server.js`) |
| --- | --- |
| Liste blanche de types | seuls `image/jpeg` et `image/png` sont acceptes |
| Contenu verifie (pas l'extension) | lecture des **magic bytes** (`FF D8 FF` / `89 50 4E 47`), pas du nom ni du type declare |
| Fichier renomme | nom aleatoire `crypto.randomBytes(16).hex + .jpg/.png` |
| Taille maximale | `multer` limite a 2 Mo -> 413 au-dela |
| Hors dossier public | stocke dans `uploads/`, servi uniquement par `/files/:id` |

Telechargement sans danger (`GET /files/:id`) :

```js
res.setHeader('Content-Type', type);              // type verifie
res.setHeader('X-Content-Type-Options', 'nosniff'); // pas de "devinette" de type
res.setHeader('Content-Disposition', 'attachment; ...'); // telecharge, pas rendu
```

Le nom est valide par `^[a-f0-9]{32}\.(jpg|png)$` (anti path traversal).

### Preuve : `.php` et `.svg` sont refuses

| Envoi | Reponse |
| --- | --- |
| Vrai PNG | `200 {ok:true, stored:"<hex>.png"}` |
| `script.php` renomme `script.jpg` | `415 type refuse : seul un vrai JPEG ou PNG est accepte` |
| `evil.svg` (contient un `<script>`) | `415 type refuse ...` |
| Fichier de 3 Mo | `413 fichier trop volumineux` |
| `/files/..%2f..%2fserver.js` | `400` |

### Que se passe-t-il si je renomme un script en .jpg et que je l'envoie ?

Il est **refuse**. L'extension `.jpg` et le type MIME declare ne sont pas crus :
le serveur lit les premiers octets du fichier. Un script (`<?php ...`, ou un SVG
`<svg>`) ne commence pas par la signature d'un JPEG (`FF D8 FF`) ou d'un PNG
(`89 50 4E 47`), donc il ne passe pas la liste blanche -> `415`.

Et meme s'il passait : le fichier serait **renomme** (plus d'extension `.php`),
**stocke hors du dossier public** (aucune URL ne l'execute), et **servi en piece
jointe avec `nosniff`** (telecharge, jamais interprete par le navigateur). Trois
barrieres independantes, pas une seule.

## Erreurs generiques (defense)

L'inverse de l'"erreur bavarde" : l'utilisateur ne voit jamais de trace
technique. Trois mesures dans `server.js` :

| Mesure | Mise en oeuvre |
| --- | --- |
| Page d'erreur generique | `respondError()` renvoie un message neutre (HTML ou JSON) + une **reference** (`errorId`), jamais de pile |
| Detail journalise cote serveur | un gestionnaire d'erreur global `app.use((err,req,res,next) => ...)` fait `console.error(errorId, err.stack)` : le detail va dans les **journaux**, pas dans la reponse |
| Debug coupe hors dev | `NODE_ENV=production` (compose) ; le detail n'est ajoute a la reponse que si `NODE_ENV=development`. En prod, message strictement generique |

En plus : 404 generique (`app.use` final) et en-tete `X-Powered-By` masque
(`app.disable('x-powered-by')`).

### Reponse vue par l'utilisateur, et ou est passe le detail

Erreur declenchee en envoyant du JSON malforme a `POST /login`.

Reponse **vue par l'utilisateur** :

```json
{ "ok": false, "error": "Une erreur est survenue. Reessayez plus tard.",
  "errorId": "8c913125b6a8" }
```

Detail, **uniquement dans les journaux du serveur** (meme errorId) :

```
[error 8c913125b6a8] SyntaxError: Expected property name or '}' in JSON ...
    at JSON.parse (<anonymous>)
    at /app/node_modules/body-parser/lib/read.js:146:18
```

Le detail (type d'erreur, pile, chemins internes) n'atteint jamais le client :
il part dans les journaux, relie a la reponse de l'utilisateur par l'`errorId`.
Pour le support, l'utilisateur n'a qu'a citer cette reference.

## Tests de securite automatises

Fichier `test/security.test.js`, lances avec le runner integre de Node :

```bash
docker compose up -d          # l'app doit tourner
npm test                      # = node --test  (BASE_URL pour cibler une autre URL)
```

Trois attaques, chacune avec une assertion precise :

| Test | Charge envoyee | Assertion (resultat sain) |
| --- | --- | --- |
| Injection SQL | `' OR '1'='1` sur `/products` et `/login` | `count === 0` (et `< ` au controle positif) ; login `401 ok:false` |
| XSS | `<img src=x onerror=alert(1)>` sur `/search` | la version **echappee** est presente ET la balise **brute** est absente |
| Upload interdit | `.php` deguise en `.jpg` sur `/upload` | statut **415**, `ok:false` |

Resultat : `pass 4  fail 0`.

### Comment on sait que l'attaque a ECHOUE (pas juste "pas plante")

Chaque test combine deux choses :

1. **Une assertion sur le resultat attendu**, pas sur l'absence de crash.
   Exemple XSS : on verifie que la reponse contient
   `&lt;img src=x onerror=alert(1)&gt;` (echappe) **et** ne contient PAS
   `<img src=x onerror=alert(1)>` (brut). Si l'app etait vulnerable
   (`innerHTML`), la balise brute serait presente et le test passerait au ROUGE.
2. **Un controle positif** : la recherche normale renvoie des resultats, un vrai
   PNG est accepte. Donc un endpoint casse (500, reponse vide) ferait echouer ce
   controle. Un test ne peut pas passer "par accident" juste parce que le serveur
   a renvoye quelque chose.

Un `200` ou un "pas d'exception" ne suffisent jamais : on verifie la **valeur**.

## Stockage des mots de passe (defense)

Inscription / connexion / deconnexion sur `GET /account` (formulaires) et en API
(`POST /register`, `/login`, `/logout`, `GET /me`).

| Mesure | Mise en oeuvre (`server.js`) |
| --- | --- |
| Hachage lent + sale | `bcrypt.hash(password, 12)` a l'inscription ; `bcrypt.compare` au login |
| Jamais de mdp en clair | on insere **uniquement** le hash ; aucun `console.log` du mot de passe ni de `req.body` |
| Session sans mdp | cookie `HttpOnly` signe (HMAC) contenant `userId.exp.signature`, pas le mot de passe |

### Le hash en base

```
 id |       email        |              pass_hash (60 car.)              
----+--------------------+-----------------------------------------------
  1 | demo@rempart.local | $2a$12$OLtDhZLOlls/4gHUKtILNO...  (bcrypt)
  2 | alice@test.local   | $2a$12$6DuXrFfoZzKv0pskbnWXdu...  (bcrypt)
```

Le prefixe `$2a$12$` indique bcrypt avec un cout de 12. Verification :

```bash
docker compose exec db psql -U rempart -d rempart \
  -c "SELECT email, pass_hash FROM app_users;"
# -> aucune ligne ne contient un mot de passe en clair
```

### Pourquoi lent et sale, et pas SHA-256 ?

- **Sale** : bcrypt genere un **sel aleatoire** par mot de passe, inclus dans le
  hash. Deux comptes avec le MEME mot de passe `identique123` donnent deux hash
  differents :
  ```
  bob   -> $2a$12$YmqC6WSgQ0o1LwSta.r0oO...
  carol -> $2a$12$h8egYF0veYKgSFKVpcW0/u...
  ```
  Sans sel (SHA-256 brut), ils seraient identiques : un attaquant casse tous les
  comptes d'un coup avec une **rainbow table** (hash precalcules).
- **Lent** : SHA-256 est concu pour etre **rapide** -> un GPU teste des milliards
  de hash/seconde, donc le brute-force d'un mot de passe vole est trivial. bcrypt
  (cout 12) est **volontairement lent** (~0,1 s par hash) et reglable : le
  brute-force devient des annees de calcul. Argon2id ajoute en plus une forte
  consommation memoire pour resister aux GPU/ASIC.

En clair : SHA-256 est une fonction de hachage *generale* (integrite), pas une
fonction de *stockage de mot de passe*. bcrypt / Argon2id sont faits pour ca :
sel integre + lenteur reglable.

### Aucun mot de passe en clair, nulle part

```bash
# en base : 0 ligne contient un mot de passe en clair
# dans les logs : aucun mot de passe (on ne journalise que l'id de l'utilisateur)
docker compose logs app | grep -i 'Demo#1234'   # -> rien
```

## Connexion discrete et freinee (defense)

Trois mesures sur `POST /login` et `POST /register` :

| Mesure | Mise en oeuvre |
| --- | --- |
| Meme message quel que soit l'echec | e-mail inconnu **et** mauvais mot de passe -> `401 identifiants invalides` (identique) |
| Pas de fuite par le timing | si l'e-mail n'existe pas, on compare quand meme contre un **hash leurre** (`DUMMY_HASH`) : meme temps de reponse |
| Tentatives limitees (compte + IP) | compteur d'echecs par e-mail (max 5) et par IP (max 20) sur 15 min -> `429` au-dela ; remis a zero a la connexion reussie |
| Longueur plutot que complexite | inscription : `password.length >= 10`, aucune regle de type "1 majuscule + 1 chiffre" |

### Que voit-on pour un compte inexistant et pour un mauvais mot de passe ?

Exactement **la meme reponse**, impossible de les distinguer :

```
# e-mail inconnu
POST /login {"email":"inconnu@nulle-part.local", ...}
-> 401 {"ok":false,"error":"identifiants invalides"}

# e-mail connu, mauvais mot de passe
POST /login {"email":"demo@rempart.local","password":"mauvais"}
-> 401 {"ok":false,"error":"identifiants invalides"}
```

Meme statut (401), meme message, meme temps de reponse. Un attaquant ne peut
donc pas **enumerer** les comptes existants (pas de "cet e-mail n'existe pas").

### Preuve de la limitation (429)

```
tentative 1..5 -> 401 identifiants invalides
tentative 6    -> 429 trop de tentatives, reessayez plus tard
```

Couvert par deux tests automatises (`test/security.test.js`) : message identique,
et passage au 429 apres le quota.

## Cookie de session durci (defense)

La session est gardee **cote serveur** (`sessions` Map : `sid -> {userId, expiresAt}`).
Le cookie ne porte qu'un **identifiant aleatoire opaque**, aucune donnee sensible.

### Les attributs du cookie, expliques

Cookie pose a la connexion :

```
Set-Cookie: session=<32 octets hex>; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600
# en production (COOKIE_SECURE=true) :  ... ; Max-Age=3600; Secure
```

| Attribut | Role |
| --- | --- |
| `session=<hex>` | identifiant de session **aleatoire** (32 octets), non devinable ; ne contient ni l'userId ni le mot de passe |
| `HttpOnly` | le cookie est **inaccessible au JavaScript** (`document.cookie`) : un XSS ne peut pas le voler |
| `SameSite=Lax` | le cookie **n'est pas envoye sur les requetes cross-site** : parade CSRF |
| `Secure` | (prod HTTPS, via `COOKIE_SECURE=true`) le cookie n'est envoye que sur une **connexion chiffree** |
| `Path=/` | le cookie vaut pour tout le site |
| `Max-Age=3600` | **expiration** cote navigateur (1 h), alignee sur le TTL serveur |

### Identifiant regenere a la connexion

Chaque `POST /login` cree une **nouvelle** session (nouvel id aleatoire) :

```
connexion 1 -> session=d16e057463b4935b...
connexion 2 -> session=8fc28b1f0ef00054...   (different : parade fixation de session)
```

### Session detruite cote serveur au logout + expiration

```
/me avec le cookie            -> 200 (connecte)
POST /logout                  -> session supprimee du store serveur
/me en REJOUANT le meme cookie -> 401 non connecte
```

Le logout ne se contente pas d'effacer le cookie : il **supprime la session du
serveur**, donc l'identifiant ne vaut plus rien meme si un attaquant en avait une
copie. Les sessions ont une **expiration** (`expiresAt`, TTL 1 h) et un balayage
periodique nettoie celles qui ont expire.

## Controle d'acces par role (defense)

Deux roles : `user` (par defaut a l'inscription) et `admin` (compte de demo).
Le controle se fait **cote serveur**, pas en masquant un lien.

### La garde (refus par defaut sur tout /admin)

```js
// server.js : montee sur le PREFIXE /admin -> couvre toutes les routes admin,
// meme futures. Une nouvelle route /admin/... est fermee tant qu'on ne
// l'ouvre pas (refus par defaut).
app.use('/admin', async (req, res, next) => {
  const user = await loadUser(req);                 // session serveur -> user
  if (!user)                 return res.status(401).json({ ok:false, error:'authentification requise' });
  if (user.role !== 'admin') return res.status(403).json({ ok:false, error:'acces refuse : role admin requis' });
  req.user = user;
  next();
});
```

### Ce que renvoie la route admin selon le role

| Appelant | `GET /admin` | `GET /admin/users` | `GET /admin/route-neuve` |
| --- | --- | --- | --- |
| Non connecte | `401` | `401` | `401` |
| Simple utilisateur | **`403` acces refuse** | **`403`** | **`403`** (refus par defaut) |
| Admin | `200` | `200` + liste | `404` (route non definie, mais pas bloquee) |

La derniere colonne montre le **refus par defaut** : meme une route inexistante
sous `/admin` renvoie `403` a un simple utilisateur, car la garde s'applique au
prefixe entier avant tout. Rien n'est seulement "masque" : c'est le serveur qui
refuse. Couvert par un test automatise (`test/security.test.js`).
