const test = require('node:test');
const assert = require('node:assert/strict');
const { ShieldBot, ShieldBotError } = require('../dist/index.js');

const base = {
  wallet: '0xa', chain_id: 56, total_approvals: 0, high_risk: 0, medium_risk: 0,
  approvals: [], alerts: [], revoke_txs: [],
};
const complete = {
  ...base, status: 'ok', total_value_at_risk_usd: 0,
  coverage: { allowances: true, balances: true, prices: true }, coverage_reasons: {},
  scanned_blocks: { from_block: 0, to_block: 100 },
};
const partial = {
  ...base, status: 'unknown', total_value_at_risk_usd: null,
  coverage: { allowances: false, balances: true, prices: true },
  coverage_reasons: { allowances: 'Approvals before block 90 not scanned' },
  scanned_blocks: { from_block: 90, to_block: 100 },
};
const nothingRead = {
  ...base, status: 'unknown', total_value_at_risk_usd: null,
  coverage: { allowances: false, balances: true, prices: true },
  coverage_reasons: { allowances: 'Approval scan unavailable: the chain RPC could not be read' },
  scanned_blocks: null,
};

const respond = body => { global.fetch = async () => ({ ok: true, json: async () => body }); };

test('a complete rescue scan is returned as ok', async () => {
  respond(complete);
  const result = await new ShieldBot().rescue('0xa', 56);
  assert.equal(result.status, 'ok');
  assert.deepEqual(result.scanned_blocks, complete.scanned_blocks);
  assert.equal(result.total_value_at_risk_usd, 0);
});

test('a partial rescue scan is returned with its unknown status', async () => {
  respond(partial);
  const result = await new ShieldBot().rescue('0xa', 56);
  assert.equal(result.status, 'unknown');
  assert.deepEqual(result.coverage_reasons, partial.coverage_reasons);
  assert.deepEqual(result.scanned_blocks, partial.scanned_blocks);
  assert.equal(result.total_value_at_risk_usd, null);
});

test('a rescue scan that read nothing throws instead of returning an empty list', async () => {
  respond(nothingRead);
  await assert.rejects(
    new ShieldBot().rescue('0xa', 56),
    error => error instanceof ShieldBotError && error.code === 'SCAN_UNAVAILABLE' && /could not be read/.test(error.message),
  );
});
