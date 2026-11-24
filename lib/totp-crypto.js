const crypto = require('node:crypto');

const ALGORITHM = 'aes-256-gcm';
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

function createTotpCipher(keyHex) {
  if (typeof keyHex !== 'string' || !/^[a-f0-9]{64}$/i.test(keyHex) || /^0+$/.test(keyHex)) {
    throw new Error('Clé TOTP invalide : fournir 32 octets aléatoires au format hexadécimal.');
  }
  const key = Buffer.from(keyHex, 'hex');
  const keyId = crypto.createHash('sha256').update(key).digest('hex').slice(0, 16);

  function encrypt(plain) {
    const nonce = crypto.randomBytes(NONCE_BYTES);
    const cipher = crypto.createCipheriv(ALGORITHM, key, nonce, { authTagLength: TAG_BYTES });
    const ciphertext = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
    return [keyId, nonce.toString('hex'), cipher.getAuthTag().toString('hex'),
      ciphertext.toString('hex')].join(':');
  }

  function decrypt(envelope) {
    const parts = envelope.split(':');
    // Les valeurs écrites avant le versionnage comportent seulement nonce, tag et chiffré.
    if (parts.length === 4 && parts.shift() !== keyId) {
      throw new Error('Version de clé TOTP inconnue.');
    }
    const [nonce, tag, ciphertext] = parts;
    if (parts.length !== 3 || !/^[a-f0-9]{24}$/.test(nonce) ||
        !/^[a-f0-9]{32}$/.test(tag) || !/^(?:[a-f0-9]{2})+$/.test(ciphertext)) {
      throw new Error('Format du secret TOTP invalide.');
    }
    const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(nonce, 'hex'),
      { authTagLength: TAG_BYTES });
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    return Buffer.concat([decipher.update(Buffer.from(ciphertext, 'hex')), decipher.final()]).toString('utf8');
  }

  return { keyId, encrypt, decrypt };
}

function rotateTotpSecret(envelope, previous, next) {
  if (envelope.startsWith(next.keyId + ':')) {
    next.decrypt(envelope); // Vérifier également l'intégrité après une reprise.
    return envelope;
  }
  return next.encrypt(previous.decrypt(envelope));
}

module.exports = { createTotpCipher, rotateTotpSecret };
