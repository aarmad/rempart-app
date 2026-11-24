-- Schema de demonstration pour le rempart "Requetes parametrees".
-- Ce fichier est joue UNE fois, a la premiere initialisation de la base,
-- par le superutilisateur postgres (via /docker-entrypoint-initdb.d).

CREATE TABLE IF NOT EXISTS products (
  id    SERIAL PRIMARY KEY,
  name  TEXT NOT NULL,
  price NUMERIC(10,2) NOT NULL
);

INSERT INTO products (name, price) VALUES
  ('Casque audio',        79.90),
  ('Clavier mecanique',   119.00),
  ('Souris sans fil',     39.50),
  ('Ecran 27 pouces',     249.00),
  ('Cable USB-C',          9.90);

CREATE TABLE IF NOT EXISTS app_users (
  id        SERIAL PRIMARY KEY,
  email     TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL,   -- hash bcrypt ($2a$...), jamais le mot de passe en clair
  role      TEXT NOT NULL DEFAULT 'user'
);

-- L'utilisateur de demo est cree au demarrage par l'app (hash bcrypt calcule
-- a l'execution), pas seme ici : aucun hash en dur dans le depot.
