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

## Utilisation de l'IA

Ce squelette a ete mis en place avec l'aide de Claude (Claude Code) :

- Generation du squelette Express, du `docker-compose.yml`, du `Dockerfile` et
  de ce README.
- Explications sur la gestion des secrets (`.env` ignore, rotation d'un secret
  deja pousse).

Tout le code a ete relu et teste manuellement avant d'etre valide. Les secrets
reels n'ont jamais ete partages avec l'IA.
