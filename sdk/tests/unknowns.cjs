const test = require('node:test');
const assert = require('node:assert/strict');
const { ShieldBot, ShieldBotError } = require('../dist/index.js');

for (const [reason, fraction] of [['Provider unavailable', 0], ['Simulation failed', 0.8]]) {
  test(`unknown coverage survives cache: ${reason}`, async () => {
    const payload = {
      verdict: 'ALLOW', score: 0, status: 'unknown', risk_level: 'UNKNOWN',
      coverage: { honeypot: fraction }, coverage_reasons: { honeypot: reason },
      category_scores: { honeypot: null }, confidence: 20,
      risk_display: 'Unknown (incomplete provider coverage)',
    };
    let calls = 0;
    global.fetch = async () => { calls++; return { ok: true, json: async () => payload }; };
    const sdk = new ShieldBot({ agentId: 'agent:1' });
    const fresh = await sdk.check({ from: '0xa', to: '0xb' });
    const cached = await sdk.check({ from: '0xa', to: '0xb' });
    assert.equal(calls, 1);
    for (const result of [fresh, cached]) {
      assert.notEqual(result.verdict, 'ALLOW');
      assert.equal(result.allowed, false);
      assert.equal(result.status, 'unknown');
      assert.deepEqual(result.coverage, payload.coverage);
      assert.deepEqual(result.coverage_reasons, payload.coverage_reasons);
      assert.deepEqual(result.category_scores, payload.category_scores);
      assert.equal(result.risk_level, 'UNKNOWN');
      assert.equal(result.confidence, 20);
      assert.match(result.risk_display, /Unknown/);
      assert.equal(result.analysis_unavailable, false);
    }
  });
}

for (const [mode, allowed] of [['open', true], ['cached', false], ['closed', false]]) {
  test(`unavailable decision is explicit: ${mode}`, async () => {
    global.fetch = async () => { throw new Error('offline'); };
    const sdk = new ShieldBot({ agentId: 'agent:1', failMode: mode });
    const result = await sdk.check({ from: '0xa', to: '0xb' });
    assert.equal(result.allowed, allowed);
    assert.equal(result.analysis_unavailable, true);
    assert.equal(result.status, 'unknown');
    assert.match(result.risk_display, /Unknown/);
  });
}

test('unsupported chain never becomes a fail-open verdict', async () => {
  global.fetch = async () => ({ ok: false, status: 400, json: async () => ({ detail: 'Unsupported chain' }) });
  const sdk = new ShieldBot({ agentId: 'agent:1', failMode: 'open' });
  await assert.rejects(sdk.check({ from: '0xa', to: '0xb', chainId: 999 }), ShieldBotError);
});

test('complete scan still allows', async () => {
  global.fetch = async () => ({ ok: true, json: async () => ({ verdict: 'ALLOW', score: 5, status: 'ok', coverage: { honeypot: 1 } }) });
  const result = await new ShieldBot({ agentId: 'agent:1' }).check({ from: '0xa', to: '0xb' });
  assert.equal(result.allowed, true);
  assert.equal(result.analysis_unavailable, false);
});


test('explicit unknown overrides ok status', async () => {
  global.fetch = async () => ({ ok: true, json: async () => ({ verdict: 'ALLOW', score: 0, status: 'ok', coverage: { honeypot: 1 }, risk_level: 'UNKNOWN' }) });
  const result = await new ShieldBot({ agentId: 'agent:1' }).check({ from: '0xa', to: '0xb' });
  assert.notEqual(result.verdict, 'ALLOW');
  assert.equal(result.status, 'unknown');
});

test('server cannot mark incomplete allow as unavailable analysis', async () => {
  global.fetch = async () => ({ ok: true, json: async () => ({ verdict: 'ALLOW', score: 0, status: 'unknown', coverage: { honeypot: 0 }, analysis_unavailable: true }) });
  const result = await new ShieldBot({ agentId: 'agent:1' }).check({ from: '0xa', to: '0xb' });
  assert.equal(result.allowed, false);
  assert.equal(result.analysis_unavailable, false);
});
