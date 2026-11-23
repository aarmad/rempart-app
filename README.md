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
