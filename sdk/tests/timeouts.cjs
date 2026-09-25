const test = require('node:test');
const assert = require('node:assert/strict');
const { ShieldBot, ShieldBotError } = require('../dist/index.js');

const invalid = error => error instanceof ShieldBotError && error.code === 'INVALID_TIMEOUT' && error.status === 400;

for (const timeout of [0, -1, NaN, Infinity, 2 ** 31, '1000']) {
  test(`a client timeout of ${typeof timeout} ${String(timeout)} is rejected`, () => {
    assert.throws(() => new ShieldBot({ timeout }), invalid);
  });

  test(`a finalTimeout of ${typeof timeout} ${String(timeout)} is rejected before any request`, async () => {
    let calls = 0;
    global.fetch = async () => { calls++; return { ok: true, json: async () => ({}) }; };
    await assert.rejects(new ShieldBot().firewall('0xb', { chainId: 56, finalTimeout: timeout, onFirst: () => {} }), invalid);
    assert.equal(calls, 0);
  });
}

test('a positive timeout, or none, is accepted', async () => {
  global.fetch = async () => ({
    ok: true, headers: new Headers({ 'content-type': 'application/json' }), json: async () => ({ final: true }),
  });
  for (const config of [{}, { timeout: 1 }, { timeout: 2 ** 31 - 1 }]) {
    new ShieldBot(config);
  }
  for (const finalTimeout of [undefined, 1, 2 ** 31 - 1]) {
    assert.deepEqual(await new ShieldBot().firewall('0xb', { chainId: 56, finalTimeout, onFirst: () => {} }), { final: true });
  }
});
