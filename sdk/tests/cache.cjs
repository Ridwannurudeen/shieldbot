const test = require('node:test');
const assert = require('node:assert/strict');
const { ShieldBot } = require('../dist/index.js');

const spender = '1'.repeat(40).padStart(64, '0');
const transaction = {
  from: '0xa', to: '0xb', chainId: 56, value: '0',
  data: `0x095ea7b3${spender}${'1'.padStart(64, '0')}`,
};
const payload = {
  verdict: 'ALLOW', score: 5, status: 'ok', coverage: { honeypot: 1 },
};

for (const [field, value] of [
  ['data', `0x095ea7b3${spender}${'f'.repeat(64)}`],
  ['from', '0xc'],
  ['value', '1'],
  ['to', '0xc'],
  ['chainId', 1],
]) {
  test(`cached allowance is not reused for different ${field}`, async () => {
    let calls = 0;
    global.fetch = async () => { calls++; return { ok: true, json: async () => payload }; };
    const sdk = new ShieldBot({ agentId: 'agent:1' });
    const fresh = await sdk.check(transaction);
    const changed = await sdk.check({ ...transaction, [field]: value });
    assert.equal(fresh.allowed, true);
    assert.equal(calls, 2);
    assert.equal(changed.cached, false);
  });
}

test('identical transaction reuses its cached allowance', async () => {
  let calls = 0;
  global.fetch = async () => { calls++; return { ok: true, json: async () => payload }; };
  const sdk = new ShieldBot({ agentId: 'agent:1' });
  await sdk.check(transaction);
  const cached = await sdk.check({ ...transaction });
  assert.equal(calls, 1);
  assert.equal(cached.allowed, true);
  assert.equal(cached.cached, true);
});

test('equivalent transaction encodings reuse the cached allowance', async () => {
  let calls = 0;
  global.fetch = async () => { calls++; return { ok: true, json: async () => payload }; };
  const sdk = new ShieldBot({ agentId: 'agent:1' });
  const mixedCase = {
    ...transaction,
    from: '0x52908400098527886E0F7030069857D2E4169EE7',
    to: '0x8617E340B3D01FA5F11F306F4090FD50E238070D',
    data: transaction.data.toUpperCase(),
    value: '0',
  };
  await sdk.check(mixedCase);
  await sdk.check({
    ...mixedCase,
    from: mixedCase.from.toLowerCase(),
    to: mixedCase.to.toLowerCase(),
    chainId: '56',
    data: mixedCase.data.toLowerCase(),
    value: '0x0',
  });
  const cached = await sdk.check({
    ...mixedCase,
    from: mixedCase.from.toLowerCase(),
    to: mixedCase.to.toLowerCase(),
    data: mixedCase.data.toLowerCase(),
    value: 0,
  });
  assert.equal(calls, 1);
  assert.equal(cached.cached, true);
});

test('hex and decimal encodings of one value share a cache entry', async () => {
  let calls = 0;
  global.fetch = async () => { calls++; return { ok: true, json: async () => payload }; };
  const sdk = new ShieldBot({ agentId: 'agent:1' });
  await sdk.check({ ...transaction, value: '0x10' });
  const cached = await sdk.check({ ...transaction, value: '16' });
  assert.equal(calls, 1);
  assert.equal(cached.cached, true);
});

for (const [name, firstValue, secondValue] of [
  ['hex and decimal values', '0x10', '10'],
]) {
  test(`${name} do not share a cache entry`, async () => {
    let calls = 0;
    global.fetch = async () => { calls++; return { ok: true, json: async () => payload }; };
    const sdk = new ShieldBot({ agentId: 'agent:1' });
    await sdk.check({ ...transaction, value: firstValue });
    const second = await sdk.check({ ...transaction, value: secondValue });
    assert.equal(calls, 2);
    assert.equal(second.cached, false);
  });
}

for (const [name, config, elapsed] of [
  ['default TTL', {}, 60_000],
  ['configured TTL', { cacheTtl: 2 }, 2_000],
  ['zero TTL', { cacheTtl: 0 }, 0],
]) {
  test(`unreachable API cannot revive allowance at ${name}`, async () => {
    const now = Date.now;
    let timestamp = 1_000_000;
    let calls = 0;
    Date.now = () => timestamp;
    global.fetch = async () => {
      calls++;
      if (calls > 1) throw new Error('offline');
      return { ok: true, json: async () => payload };
    };
    try {
      const sdk = new ShieldBot({ agentId: 'agent:1', ...config });
      const fresh = await sdk.check(transaction);
      assert.equal(fresh.allowed, true);
      timestamp += elapsed;
      const expired = await sdk.check(transaction);
      assert.equal(expired.allowed, false);
      assert.equal(expired.verdict, 'WARN');
      assert.equal(expired.cached, false);
      assert.equal(expired.analysis_unavailable, true);
      assert.equal(calls, 2);
    } finally {
      Date.now = now;
    }
  });
}
