#!/bin/bash
# Cree le compte applicatif au MOINDRE PRIVILEGE.
# Joue a la premiere init de la base, par le superutilisateur postgres.
#
# Le compte "rempart" (POSTGRES_USER) est superutilisateur : on ne s'en sert
# PAS pour l'application. L'app se connecte avec APP_DB_USER, qui ne peut QUE
# lire les deux tables de demo. Pas de DROP, pas d'INSERT, pas de superuser.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
  -- Role applicatif : peut se connecter, rien de plus par defaut.
  CREATE ROLE ${APP_DB_USER} LOGIN PASSWORD '${APP_DB_PASSWORD}'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;

  GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO ${APP_DB_USER};
  GRANT USAGE ON SCHEMA public TO ${APP_DB_USER};

  -- Moindre privilege : products en LECTURE SEULE.
  GRANT SELECT ON products TO ${APP_DB_USER};

  -- app_users : lecture + insertion (l'inscription cree des comptes).
  -- Toujours PAS d'UPDATE ni de DELETE.
  GRANT SELECT, INSERT ON app_users TO ${APP_DB_USER};
  GRANT USAGE, SELECT ON SEQUENCE app_users_id_seq TO ${APP_DB_USER};
EOSQL

echo "Role applicatif ${APP_DB_USER} cree (lecture seule)."
