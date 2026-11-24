const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');

const base = process.env.BASE_URL || 'https://localhost';
const png = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jkHkAAAAASUVORK5CYII=',
  'base64'
);

test('la suppression confirmée efface le compte et invalide ses autres sessions', async () => {
  const email = 'effacement-' + randomUUID() + '@example.test';
  const password = randomUUID();
  const csrfResponse = await fetch(base + '/csrf');
  const { csrfToken } = await csrfResponse.json();
  const csrfCookie = 'csrf=' + csrfToken;

  function request(path, { method = 'GET', session, body } = {}) {
    const headers = { Accept: 'application/json', Cookie: [csrfCookie, session].filter(Boolean).join('; ') };
    if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken;
    if (body && !(body instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(body);
    }
    return fetch(base + path, { method, headers, body });
  }

  function sessionCookie(response) {
    return response.headers.getSetCookie().find((cookie) => cookie.startsWith('session=')).split(';')[0];
  }

  const registration = await request('/register', { method: 'POST', body: { email, password } });
  assert.equal(registration.status, 201);
  const first = sessionCookie(registration);
  const login = await request('/login', { method: 'POST', body: { email, password } });
  assert.equal(login.status, 200);
  const second = sessionCookie(login);
  assert.notEqual(first, second);

  const account = await request('/account', { session: first });
  assert.match(await account.text(), /action="\/account\/delete"/);
  const note = await request('/notes', { method: 'POST', session: first, body: { text: 'Note de test à effacer' } });
  assert.equal(note.status, 201);

  const form = new FormData();
  form.append('file', new Blob([png], { type: 'image/png' }), 'test.png');
  const upload = await request('/upload', { method: 'POST', session: first, body: form });
  assert.equal(upload.status, 200);
  const { url } = await upload.json();
  assert.equal((await request(url, { session: second })).status, 200);

  const incomplete = await request('/account/delete', { method: 'POST', session: first, body: { password } });
  assert.equal(incomplete.status, 400);
  assert.equal((await request('/me', { session: second })).status, 200);

  const deletion = await fetch(base + '/account/delete', {
    method: 'POST',
    headers: { Cookie: [csrfCookie, first].join('; ') },
    body: new URLSearchParams({ _csrf: csrfToken, password, confirm: 'yes' }),
    redirect: 'manual',
  });
  assert.equal(deletion.status, 303);
  assert.equal(deletion.headers.get('location'), '/account?deleted=1');
  assert.match(deletion.headers.getSetCookie().join('\n'), /session=;.*Max-Age=0/);
  const confirmation = await request(deletion.headers.get('location'));
  assert.match(await confirmation.text(), /Votre compte a été supprimé/);
  for (const session of [first, second]) {
    assert.equal((await request('/me', { session })).status, 401);
    assert.equal((await request(url, { session })).status, 404);
  }
  assert.equal((await request('/login', { method: 'POST', body: { email, password } })).status, 401);
});
