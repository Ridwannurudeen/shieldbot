const test = require('node:test');
const assert = require('node:assert/strict');
const { ShieldBot, ShieldBotError, SUPPORTED_CHAIN_IDS, isSupportedChainId } = require('../dist/index.js');

const complete = { verdict: 'ALLOW', score: 0, status: 'ok', coverage: { honeypot: 1 } };

test('Robinhood Chain is a supported chain', () => {
  assert.ok(SUPPORTED_CHAIN_IDS.includes(4663));
  assert.equal(isSupportedChainId(4663), true);
  assert.equal(isSupportedChainId(999), false);
});

test('an unlisted chain is left to the API to reject', async () => {
  let calls = 0;
  global.fetch = async () => { calls++; return { ok: false, status: 400, json: async () => ({ detail: 'Unsupported chain ID 999' }) }; };
  await assert.rejects(new ShieldBot().scan('0xb', { chainId: 999 }), error => error instanceof ShieldBotError && error.status === 400);
  assert.equal(calls, 1);
});

for (const [name, call] of [
  ['scan', sdk => sdk.scan('0xb')],
  ['firewall', sdk => sdk.firewall('0xb', { from: '0xa' })],
  ['check', sdk => sdk.check({ from: '0xa', to: '0xb' })],
  ['rescue', sdk => sdk.rescue('0xa')],
  ['queryThreatGraph', sdk => sdk.queryThreatGraph('0xb')],
]) {
  test(`${name} without a chain is rejected before any request`, async () => {
    let calls = 0;
    global.fetch = async () => { calls++; return { ok: true, json: async () => complete }; };
    const sdk = new ShieldBot({ agentId: 'agent:1', failMode: 'open' });
    await assert.rejects(call(sdk), error => error instanceof ShieldBotError && error.code === 'MISSING_CHAIN_ID');
    assert.equal(calls, 0);
  });
}

test('the requested chain reaches the API unchanged', async () => {
  const requests = [];
  global.fetch = async (url, init) => {
    requests.push({ url, body: init.body ? JSON.parse(init.body) : undefined });
    return { ok: true, json: async () => complete };
  };
  const sdk = new ShieldBot({ agentId: 'agent:1' });
  await sdk.scan('0xb', { chainId: 4663 });
  await sdk.firewall('0xb', { chainId: 4663 });
  await sdk.check({ from: '0xa', to: '0xb', chainId: 4663 });
  await sdk.rescue('0xa', 4663);
  await sdk.queryThreatGraph('0xb', 4663);
  assert.equal(requests[0].body.chainId, 4663);
  assert.equal(requests[1].body.chainId, 4663);
  assert.equal(requests[2].body.transaction.chain_id, 4663);
  assert.equal(new URL(requests[3].url).searchParams.get('chain_id'), '4663');
  assert.equal(new URL(requests[4].url).searchParams.get('chain_id'), '4663');
});
