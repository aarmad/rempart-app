#!/bin/sh
# Initialisation d'une nouvelle base ou migration d'un volume existant.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v app_role="$APP_DB_USER" <<'SQL'
BEGIN;

-- Les volumes créés avant l'arrivée des comptes et de la 2FA ont besoin
-- des mêmes tables que les installations neuves.
CREATE TABLE IF NOT EXISTS notes (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  text TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS user_totp (
  user_id INTEGER PRIMARY KEY REFERENCES app_users(id) ON DELETE CASCADE,
  secret_enc TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS backup_codes (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at TIMESTAMPTZ
);

ALTER TABLE notes DROP CONSTRAINT IF EXISTS notes_user_id_fkey,
  ADD CONSTRAINT notes_user_id_fkey FOREIGN KEY (user_id) REFERENCES app_users(id) ON DELETE CASCADE;
ALTER TABLE user_totp DROP CONSTRAINT IF EXISTS user_totp_user_id_fkey,
  ADD CONSTRAINT user_totp_user_id_fkey FOREIGN KEY (user_id) REFERENCES app_users(id) ON DELETE CASCADE;
ALTER TABLE backup_codes DROP CONSTRAINT IF EXISTS backup_codes_user_id_fkey,
  ADD CONSTRAINT backup_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES app_users(id) ON DELETE CASCADE;

CREATE TABLE IF NOT EXISTS app_sessions (
  sid_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS account_files (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  content BYTEA NOT NULL CHECK (octet_length(content) <= 2097152)
);

CREATE INDEX IF NOT EXISTS notes_user_id_idx ON notes (user_id);
CREATE INDEX IF NOT EXISTS backup_codes_user_id_idx ON backup_codes (user_id);
CREATE INDEX IF NOT EXISTS app_sessions_user_id_idx ON app_sessions (user_id);
CREATE INDEX IF NOT EXISTS app_sessions_expires_at_idx ON app_sessions (expires_at);
CREATE INDEX IF NOT EXISTS account_files_user_id_idx ON account_files (user_id);

GRANT SELECT, INSERT, DELETE ON app_users TO :"app_role";
GRANT USAGE, SELECT ON SEQUENCE app_users_id_seq TO :"app_role";
GRANT SELECT, INSERT, UPDATE ON notes, user_totp TO :"app_role";
GRANT SELECT, INSERT, UPDATE, DELETE ON backup_codes TO :"app_role";
GRANT USAGE, SELECT ON SEQUENCE notes_id_seq, backup_codes_id_seq TO :"app_role";
GRANT SELECT, INSERT, DELETE ON app_sessions TO :"app_role";
GRANT SELECT, INSERT ON account_files TO :"app_role";

COMMIT;
SQL
