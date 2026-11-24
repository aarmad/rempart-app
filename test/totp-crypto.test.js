const test = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { createTotpCipher, rotateTotpSecret } = require('../lib/totp-crypto');

test('chiffre le même secret avec deux nonces différents et authentifie le chiffré', () => {
  const cipher = createTotpCipher(randomBytes(32).toString('hex'));
  const secret = 'SECRET-TOTP-DE-TEST';
  const first = cipher.encrypt(secret);
  const second = cipher.encrypt(secret);
  assert.notEqual(first.split(':')[1], second.split(':')[1]);
  assert.equal(first.split(':')[1].length, 24);
  assert.equal(cipher.decrypt(first), secret);
  assert.equal(cipher.decrypt(second), secret);
  const tampered = first.slice(0, -1) + (first.endsWith('0') ? '1' : '0');
  assert.throws(() => cipher.decrypt(tampered));
});

test('refuse les clés absentes, incomplètes ou nulles', () => {
  for (const key of [undefined, '', '1234', '0'.repeat(64)]) {
    assert.throws(() => createTotpCipher(key));
  }
});

test('rotate les formats anciens et récents et reprend sans rechiffrer deux fois', () => {
  const previous = createTotpCipher(randomBytes(32).toString('hex'));
  const next = createTotpCipher(randomBytes(32).toString('hex'));
  const secret = 'SECRET-TOTP-DE-TEST';
  const original = previous.encrypt(secret);
  const legacy = original.split(':').slice(1).join(':');
  assert.equal(previous.decrypt(legacy), secret);
  for (const stored of [original, legacy]) {
    const rotated = rotateTotpSecret(stored, previous, next);
    assert.equal(next.decrypt(rotated), secret);
    assert.throws(() => previous.decrypt(rotated));
    assert.equal(rotateTotpSecret(rotated, previous, next), rotated);
  }
});
