const test = require('node:test');
const assert = require('node:assert/strict');
const { ShieldBot, ShieldBotError } = require('../dist/index.js');

const complete = { verdict: 'ALLOW', score: 0, status: 'ok', coverage: { honeypot: 1 } };
const calls = {
  check: (sdk, value) => sdk.check({ from: '0xa', to: '0xb', chainId: 56, value }),
  firewall: (sdk, value) => sdk.firewall('0xb', { chainId: 56, value }),
};
const sentValue = {
  check: body => body.transaction.value,
  firewall: body => body.value,
};

for (const method of Object.keys(calls)) {
  for (const [value, sent] of [
    ['0x10', '16'],
    ['0X10', '16'],
    ['16', '16'],
    [' 16 ', '16'],
    [16, '16'],
    [16n, '16'],
    [undefined, '0'],
  ]) {
    test(`${method} sends ${typeof value} value ${JSON.stringify(String(value))} as decimal wei`, async () => {
      const bodies = [];
      global.fetch = async (url, init) => { bodies.push(JSON.parse(init.body)); return { ok: true, json: async () => complete }; };
      await calls[method](new ShieldBot({ agentId: 'agent:1' }), value);
      assert.equal(sentValue[method](bodies[0]), sent);
    });
  }

  for (const value of ['not-a-number', '', '-1', '0b1', '1.5', '1e18', '1_000', null, 1.5, -1, 2 ** 60, -1n, true]) {
    test(`${method} rejects ${typeof value} value ${JSON.stringify(String(value))} before any request`, async () => {
      let requests = 0;
      global.fetch = async () => { requests++; return { ok: true, json: async () => complete }; };
      const sdk = new ShieldBot({ agentId: 'agent:1', failMode: 'open' });
      await assert.rejects(calls[method](sdk, value), error => error instanceof ShieldBotError && error.code === 'INVALID_VALUE');
      assert.equal(requests, 0);
    });
  }
}
