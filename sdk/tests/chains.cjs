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

const target = '0x' + 'b'.repeat(40);
for (const [name, call] of [
  ['scan', (sdk, chainId) => sdk.scan(target, { chainId })],
  ['firewall', (sdk, chainId) => sdk.firewall(target, { chainId })],
  ['check', (sdk, chainId) => sdk.check({ from: '0xa', to: target, chainId })],
  ['rescue', (sdk, chainId) => sdk.rescue(target, chainId)],
  ['queryThreatGraph', (sdk, chainId) => sdk.queryThreatGraph(target, { chainId })],
]) {
  for (const chainId of ['56', '0x38', 56.5, 0, -1, NaN, Infinity, 2 ** 53, 56n, true]) {
    test(`${name} rejects ${typeof chainId} chain ${String(chainId)} before any request`, async () => {
      let calls = 0;
      global.fetch = async () => { calls++; return { ok: true, json: async () => complete }; };
      const sdk = new ShieldBot({ agentId: 'agent:1', failMode: 'open' });
      await assert.rejects(call(sdk, chainId), error => error instanceof ShieldBotError && error.code === 'INVALID_CHAIN_ID');
      assert.equal(calls, 0);
    });
  }
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
  await sdk.queryThreatGraph('0xb', { chainId: 4663 });
  assert.equal(requests[0].body.chainId, 4663);
  assert.equal(requests[1].body.chainId, 4663);
  assert.equal(requests[2].body.transaction.chain_id, 4663);
  assert.equal(new URL(requests[3].url).searchParams.get('chain_id'), '4663');
  assert.equal(new URL(requests[4].url).searchParams.get('chain_id'), '4663');
});

test('queryThreatGraph takes its chain and depth as options', async () => {
  const urls = [];
  global.fetch = async (url) => { urls.push(new URL(url)); return { ok: true, json: async () => ({}) }; };
  const sdk = new ShieldBot();
  await sdk.queryThreatGraph(target, { chainId: 4663, maxDepth: 2 });
  await sdk.queryThreatGraph(target, { chainId: 1 });
  assert.deepEqual(
    urls.map((url) => [url.searchParams.get('chain_id'), url.searchParams.get('max_depth')]),
    [['4663', '2'], ['1', '3']],
  );
});

test('queryThreatGraph written the old way, with a depth second, is rejected instead of read as a chain', async () => {
  let calls = 0;
  global.fetch = async () => { calls++; return { ok: true, json: async () => ({}) }; };
  await assert.rejects(
    new ShieldBot().queryThreatGraph(target, 1),
    error => error instanceof ShieldBotError && error.code === 'MISSING_CHAIN_ID',
  );
  assert.equal(calls, 0);
});
