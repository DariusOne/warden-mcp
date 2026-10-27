import assert from 'node:assert/strict';
import test from 'node:test';
import { metadata, SecretFilter } from './filter.js';

test('known secrets are filtered in text, keys, structures and common encodings', () => {
  const secret = 'Synthet!c + 密码 / 93',
    filter = new SecretFilter();
  filter.add(secret, '123456');
  const values = [
    secret,
    encodeURIComponent(secret),
    Buffer.from(secret).toString('base64'),
    Buffer.from(secret).toString('hex'),
    JSON.stringify(secret).slice(1, -1),
  ];
  for (const value of values)
    assert.equal(
      filter.text(`before ${value} after`),
      'before [REDACTED] after',
    );
  assert.deepEqual(filter.clean({ [secret]: [secret, 123456] }), {
    '[REDACTED]': ['[REDACTED]', '[REDACTED]'],
  });
  assert.equal(filter.text('ordinary text'), 'ordinary text');
  assert.ok(!JSON.stringify(filter).includes(secret));
});

test('metadata is an allowlist and URL credentials/query/fragment never survive', () => {
  const item = {
    id: 'id',
    name: 'name',
    type: 1,
    notes: 'note-secret',
    fields: [{ type: 0, value: 'plain-field-secret' }],
    login: {
      username: 'user',
      password: 'pass-secret',
      totp: 'otp-secret',
      uris: [
        {
          uri: 'https://user:uri-secret@example.invalid:8443/login?token=url-secret#fragment-secret',
        },
      ],
    },
  };
  const f = new SecretFilter();
  f.item(item);
  const result = metadata(item);
  assert.deepEqual(Object.keys(result), [
    'id',
    'name',
    'type',
    'username',
    'website_origins',
    'has_password',
    'has_totp',
  ]);
  assert.deepEqual(result.website_origins, ['https://example.invalid:8443']);
  for (const v of [
    'note-secret',
    'plain-field-secret',
    'pass-secret',
    'otp-secret',
    'uri-secret',
    'url-secret',
    'fragment-secret',
  ])
    assert.equal(f.text(v), '[REDACTED]');
});

test('overlapping secrets and short secrets do not expose suffixes', () => {
  const f = new SecretFilter();
  f.add('abc', 'cdef');
  assert.equal(f.text('xabcdefy'), 'x[REDACTED]y');
});

test('nonsecret routing fields never corrupt stable IDs or allowed origins', () => {
  const item = {
    id: '11223344-2222-3333-4444-555555555555',
    name: 'SSH',
    type: 1,
    fields: [
      { name: 'port', value: '22', type: 0 },
      { name: 'host', value: 'example.invalid', type: 0 },
      { name: 'ordinary', value: 'keep-hidden', type: 0 },
    ],
    login: {
      password: 'native-secret',
      uris: [{ uri: 'https://example.invalid/' }],
    },
  };
  const f = new SecretFilter();
  f.item(item);
  const result = f.clean(metadata(item));
  assert.deepEqual(result, metadata(item));
  assert.equal(f.text('keep-hidden native-secret'), '[REDACTED] [REDACTED]');
});
