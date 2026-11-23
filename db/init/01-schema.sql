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
  pass_hash TEXT NOT NULL,   -- format "salt:hash" (scrypt), jamais en clair
  role      TEXT NOT NULL DEFAULT 'user'
);

-- Utilisateur de demo. Mot de passe : Demo#1234 (hash scrypt ci-dessous).
INSERT INTO app_users (email, pass_hash, role) VALUES
  ('demo@rempart.local',
   '1d1218831f3284e47150138cd1f5492b:f45c100733220a187d4b142ea2d121a70c69fed7ad8bac68f20094b1ccfcd95fd3c56e6fa8515492180e5fb6059c6d757bc458bb82d13a05323c2b8b3746a506',
   'admin');
