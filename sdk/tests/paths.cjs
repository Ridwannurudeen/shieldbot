const test = require('node:test');
const assert = require('node:assert/strict');
const { ShieldBot, ShieldBotError } = require('../dist/index.js');

const address = '0x52908400098527886E0F7030069857D2E4169EE7';
const calls = {
  rescue: (sdk, target) => sdk.rescue(target, 4663),
  getCampaign: (sdk, target) => sdk.getCampaign(target),
  queryThreatGraph: (sdk, target) => sdk.queryThreatGraph(target, { chainId: 4663 }),
};
const rescued = {
  wallet: address, chain_id: 4663, status: 'ok', coverage: {}, coverage_reasons: {},
  scanned_blocks: { from_block: 0, to_block: 100 }, total_approvals: 0, high_risk: 0, medium_risk: 0,
  total_value_at_risk_usd: 0, approvals: [], alerts: [], revoke_txs: [],
};

for (const [method, call] of Object.entries(calls)) {
  for (const [name, target] of [
    ['a short address', '0xa'],
    ['an address with a trailing #, which drops the chain', `${address}#`],
    ['an address carrying its own chain_id', `${address}?chain_id=1&`],
    ['a path traversal to another route', '../usage'],
    ['a traversal after a valid address', `${address}/../../usage`],
    ['39 hex digits', address.slice(0, -1)],
    ['41 hex digits', `${address}0`],
    ['a non-hex digit', `${address.slice(0, -1)}g`],
    ['an uppercase 0X prefix', `0X${address.slice(2)}`],
    ['a trailing newline', `${address}\n`],
    ['a leading space', ` ${address}`],
    ['no address', undefined],
  ]) {
    test(`${method} rejects ${name} before any request`, async () => {
      let requests = 0;
      global.fetch = async () => { requests++; return { ok: true, json: async () => rescued }; };
      await assert.rejects(call(new ShieldBot(), target), error => error instanceof ShieldBotError && error.code === 'INVALID_ADDRESS');
      assert.equal(requests, 0);
    });
  }

  test(`${method} puts a valid address in the path as it is`, async () => {
    const urls = [];
    global.fetch = async (url) => { urls.push(new URL(url)); return { ok: true, json: async () => rescued }; };
    await call(new ShieldBot(), address);
    assert.match(urls[0].pathname, new RegExp(`/${address}$`));
  });
}

for (const method of ['rescue', 'queryThreatGraph']) {
  test(`${method} rejects an answer for a chain other than the one asked for`, async () => {
    global.fetch = async () => ({ ok: true, json: async () => ({ ...rescued, chain_id: 56 }) });
    await assert.rejects(
      calls[method](new ShieldBot(), address),
      error => error instanceof ShieldBotError && error.code === 'CHAIN_MISMATCH' && error.status === 502,
    );
  });

  test(`${method} accepts an answer that names the chain asked for, or none`, async () => {
    for (const answer of [rescued, (({ chain_id, ...rest }) => rest)(rescued)]) {
      global.fetch = async () => ({ ok: true, json: async () => answer });
      assert.deepEqual(await calls[method](new ShieldBot(), address), answer);
    }
  });
}
