const test = require('node:test');
const assert = require('node:assert/strict');
const { ShieldBot, ShieldBotError } = require('../dist/index.js');

const IMPACT = { sending: 'Tokens', granting_access: 'None', recipient: '0xb', post_tx_state: 'Unknown (analysis in progress)' };
const FIRST = {
  status: 'unknown', classification: 'BLOCK_RECOMMENDED', risk_score: 90,
  risk_display: 'Unknown (analysis in progress)', danger_signals: ['Confirmed scam address'],
  verdict: 'BLOCK_RECOMMENDED — Unknown (analysis in progress)', transaction_impact: IMPACT,
  partial: true, failed_sources: [], final: false, pending_sources: ['honeypot'], elapsed_ms: 12,
};
const FINAL = {
  status: 'ok', classification: 'BLOCK_RECOMMENDED', risk_score: 90, risk_display: '90%',
  danger_signals: ['Confirmed scam address'], verdict: 'BLOCK_RECOMMENDED — Rug probability 90%',
  transaction_impact: { ...IMPACT, post_tx_state: 'Risk archetype: High-Risk Contract' },
  evidence_hash: '0x' + 'ab'.repeat(32), final: true,
};

const sse = (event, data) => `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
const flush = () => new Promise((resolve) => setImmediate(resolve));

/** A fetch that answers with an event stream the test writes to; like fetch, it errors the stream on abort. */
function streamingFetch() {
  let controller;
  let cancels = 0;
  const stream = new ReadableStream({ start(c) { controller = c; } });
  // Counts the SDK's reader.cancel() calls, which a closed stream would not report to its source.
  const body = {
    getReader() {
      const reader = stream.getReader();
      return { read: () => reader.read(), cancel: (reason) => { cancels += 1; return reader.cancel(reason); } };
    },
  };
  const requests = [];
  return {
    requests,
    cancelled: () => cancels > 0,
    fetch: async (url, init) => {
      requests.push(init);
      init.signal.addEventListener('abort', () => controller.error(Object.assign(new Error('aborted'), { name: 'AbortError' })));
      return { ok: true, status: 200, headers: new Headers({ 'content-type': 'text/event-stream' }), body };
    },
    write: (text) => controller.enqueue(new TextEncoder().encode(text)),
    writeBytes: (bytes) => controller.enqueue(bytes),
    end: () => controller.close(),
  };
}

test('a streamed call gives onFirst the interim verdict, then resolves with the final', async () => {
  const stream = streamingFetch();
  global.fetch = stream.fetch;
  const seen = [];
  stream.write(sse('first', FIRST));
  stream.write(sse('final', FINAL));
  stream.end();

  const result = await new ShieldBot().firewall('0xb', { chainId: 56, onFirst: (first) => seen.push(first) });
  seen.push('resolved');

  assert.deepEqual(seen, [FIRST, 'resolved']);
  assert.equal(seen[0].final, false);
  assert.equal(seen[0].status, 'unknown');
  assert.deepEqual(result, FINAL);
  assert.equal(stream.requests[0].headers.Accept, 'text/event-stream');
});

test('events split across chunks, even inside a character, are read whole', async () => {
  const stream = streamingFetch();
  global.fetch = stream.fetch;
  // One byte per chunk splits every em dash; the final also uses CRLF line ends.
  const bytes = new TextEncoder().encode(sse('first', FIRST) + sse('final', FINAL).replace(/\n/g, '\r\n'));
  for (const byte of bytes) {
    stream.writeBytes(new Uint8Array([byte]));
  }
  stream.end();
  const firsts = [];

  const result = await new ShieldBot().firewall('0xb', { chainId: 56, onFirst: (first) => firsts.push(first) });

  assert.deepEqual(firsts, [FIRST]);
  assert.deepEqual(result, FINAL);
});

// The first event with its JSON split over three data lines, one of them with no space after the colon.
function multiLineFirst() {
  const [head, ...rest] = JSON.stringify(FIRST).split(',');
  return `event: first\ndata: ${head},\ndata: ${rest.slice(0, 3).join(',')},\ndata:${rest.slice(3).join(',')}\n\n`;
}

test('data lines are joined with LF, and a lone CR ends a line', async () => {
  const stream = streamingFetch();
  global.fetch = stream.fetch;
  stream.write((multiLineFirst() + sse('final', FINAL)).replace(/\n/g, '\r'));
  stream.end();
  const firsts = [];

  const result = await new ShieldBot().firewall('0xb', { chainId: 56, onFirst: (first) => firsts.push(first) });

  assert.deepEqual(firsts, [FIRST]);
  assert.deepEqual(result, FINAL);
});

test('a CRLF split between chunks ends one line, not two', async () => {
  const stream = streamingFetch();
  global.fetch = stream.fetch;
  // Every chunk boundary falls between a CR and its LF, inside a multi-line event.
  for (const part of (multiLineFirst() + sse('final', FINAL)).replace(/\n/g, '\r\n').split('\n')) {
    stream.write(part);
    stream.write('\n');
  }
  stream.end();
  const firsts = [];

  const result = await new ShieldBot().firewall('0xb', { chainId: 56, onFirst: (first) => firsts.push(first) });

  assert.deepEqual(firsts, [FIRST]);
  assert.deepEqual(result, FINAL);
});

test('an exception from onFirst rejects the call unchanged and releases the stream', async () => {
  const stream = streamingFetch();
  global.fetch = stream.fetch;
  stream.write(sse('first', FIRST));
  const failure = new TypeError('the caller broke');

  await assert.rejects(
    new ShieldBot().firewall('0xb', { chainId: 56, onFirst: () => { throw failure; } }),
    (error) => error === failure,
  );
  assert.equal(stream.cancelled(), true);
});

test('a promise from onFirst that rejects rejects the call with its error and releases the stream', async () => {
  const stream = streamingFetch();
  global.fetch = stream.fetch;
  stream.write(sse('first', FIRST));
  stream.write(sse('final', FINAL));
  stream.end();
  const failure = new TypeError('the caller broke later');

  await assert.rejects(
    new ShieldBot().firewall('0xb', { chainId: 56, onFirst: async () => { await flush(); throw failure; } }),
    (error) => error === failure,
  );
  assert.equal(stream.cancelled(), true);
});

test('the stream is read on only once a promise from onFirst settles', async () => {
  const stream = streamingFetch();
  global.fetch = stream.fetch;
  stream.write(sse('first', FIRST));
  stream.write(sse('final', FINAL));
  stream.end();
  let finish;
  const seen = [];

  const pending = new ShieldBot().firewall('0xb', {
    chainId: 56,
    onFirst: () => new Promise((resolve) => { finish = resolve; }),
  });
  pending.then(() => seen.push('resolved'));
  await flush();
  await flush();
  seen.push('listener settles');
  finish();

  assert.deepEqual(await pending, FINAL);
  assert.deepEqual(seen, ['listener settles', 'resolved']);
});

test('the stream is released once the final arrives', async () => {
  const stream = streamingFetch();
  global.fetch = stream.fetch;
  stream.write(sse('final', FINAL));

  assert.deepEqual(await new ShieldBot().firewall('0xb', { chainId: 56, onFirst: () => {} }), FINAL);
  assert.equal(stream.cancelled(), true);
});

test('an error event rejects with the API status and no final', async () => {
  const stream = streamingFetch();
  global.fetch = stream.fetch;
  const firsts = [];
  stream.write(sse('first', FIRST));
  stream.write(sse('error', { status: 500, detail: 'Internal server error' }));
  stream.write(sse('final', FINAL));
  stream.end();

  await assert.rejects(
    new ShieldBot().firewall('0xb', { chainId: 56, onFirst: (first) => firsts.push(first) }),
    (error) => error instanceof ShieldBotError && error.status === 500 && error.code === 'STREAM_ERROR' && /Internal server error/.test(error.message),
  );
  assert.equal(firsts.length, 1);
  assert.equal(stream.cancelled(), true);
});

for (const [name, data, status, message] of [
  ['a 4xx status', { status: 400, detail: 'Invalid calldata' }, 400, /Invalid calldata/],
  ['no status', { detail: 'Scan failed' }, 500, /Scan failed/],
  ['no status or detail', {}, 500, /HTTP 500/],
]) {
  test(`an error event with ${name} rejects with code STREAM_ERROR and status ${status}`, async () => {
    const stream = streamingFetch();
    global.fetch = stream.fetch;
    stream.write(sse('error', data));
    stream.end();

    await assert.rejects(
      new ShieldBot().firewall('0xb', { chainId: 56, onFirst: () => {} }),
      (error) => error instanceof ShieldBotError && error.code === 'STREAM_ERROR' && error.status === status && message.test(error.message),
    );
  });
}

test('a stream with only the final never calls onFirst', async () => {
  const stream = streamingFetch();
  global.fetch = stream.fetch;
  let called = false;
  stream.write(sse('final', FINAL));
  stream.end();

  const result = await new ShieldBot().firewall('0xb', { chainId: 56, onFirst: () => { called = true; } });

  assert.equal(called, false);
  assert.deepEqual(result, FINAL);
});

test('a stream that ends without a final rejects instead of resolving', async () => {
  const stream = streamingFetch();
  global.fetch = stream.fetch;
  stream.write(sse('first', FIRST));
  stream.end();

  await assert.rejects(
    new ShieldBot().firewall('0xb', { chainId: 56, onFirst: () => {} }),
    (error) => error instanceof ShieldBotError && error.code === 'NETWORK_ERROR',
  );
  assert.equal(stream.cancelled(), true);
});

test('data lines are joined with LF, not glued: a JSON token split over two lines does not parse', async () => {
  const stream = streamingFetch();
  global.fetch = stream.fetch;
  // Glued, these two lines would read as {"status":"unknown"}; joined with LF the string holds a raw
  // line break, which JSON refuses. The reader is released either way.
  stream.write('event: first\ndata: {"status":"unkn\ndata: own"}\n\n');
  stream.write(sse('final', FINAL));
  stream.end();
  let called = false;

  await assert.rejects(
    new ShieldBot().firewall('0xb', { chainId: 56, onFirst: () => { called = true; } }),
    (error) => error instanceof ShieldBotError && error.code === 'NETWORK_ERROR',
  );
  assert.equal(called, false);
  assert.equal(stream.cancelled(), true);
});

test('an empty line ends an event: the next one does not inherit its name', async () => {
  const stream = streamingFetch();
  global.fetch = stream.fetch;
  // A named event with no data, then data with no name: not a first.
  stream.write(`event: first\n\ndata: ${JSON.stringify(FIRST)}\n\n`);
  stream.write(sse('final', FINAL));
  stream.end();
  let called = false;

  const result = await new ShieldBot().firewall('0xb', { chainId: 56, onFirst: () => { called = true; } });

  assert.equal(called, false);
  assert.deepEqual(result, FINAL);
});

const withoutKey = (key) => { const copy = { ...FIRST }; delete copy[key]; return copy; };
for (const [name, first] of [
  ['status ok', { ...FIRST, status: 'ok' }],
  ['no status', withoutKey('status')],
  ['classification SAFE', { ...FIRST, classification: 'SAFE' }],
  ['classification safe', { ...FIRST, classification: 'safe' }],
  ['classification caution', { ...FIRST, classification: 'caution' }],
  ['classification UNKNOWN', { ...FIRST, classification: 'UNKNOWN' }],
  ['no classification', withoutKey('classification')],
  ['final true', { ...FIRST, final: true }],
  ['no final', withoutKey('final')],
  ['final as a string', { ...FIRST, final: 'false' }],
]) {
  test(`a first event with ${name} never reaches onFirst`, async () => {
    const stream = streamingFetch();
    global.fetch = stream.fetch;
    stream.write(sse('first', first));
    stream.write(sse('first', FIRST));
    stream.write(sse('final', FINAL));
    stream.end();
    const firsts = [];

    const result = await new ShieldBot().firewall('0xb', { chainId: 56, onFirst: (seen) => firsts.push(seen) });

    assert.deepEqual(firsts, [FIRST]);
    assert.deepEqual(result, FINAL);
  });
}

for (const classification of ['CAUTION', 'HIGH_RISK', 'BLOCK_RECOMMENDED']) {
  test(`a first classified ${classification} reaches onFirst`, async () => {
    const stream = streamingFetch();
    global.fetch = stream.fetch;
    const first = { ...FIRST, classification };
    stream.write(sse('first', first));
    stream.write(sse('final', FINAL));
    stream.end();
    const firsts = [];

    await new ShieldBot().firewall('0xb', { chainId: 56, onFirst: (seen) => firsts.push(seen) });

    assert.deepEqual(firsts, [first]);
  });
}

test('a plain JSON answer to a streamed request (STRICT) resolves with it', async () => {
  const strict = { ...FINAL, policy_mode: 'STRICT' };
  delete strict.final;
  global.fetch = async () => ({ ok: true, headers: new Headers({ 'content-type': 'application/json' }), json: async () => strict });
  let called = false;

  const result = await new ShieldBot().firewall('0xb', { chainId: 56, onFirst: () => { called = true; } });

  assert.equal(called, false);
  assert.deepEqual(result, strict);
});

test('without onFirst there is no Accept header and the plain path is used', async () => {
  const requests = [];
  global.fetch = async (url, init) => { requests.push(init); return { ok: true, json: async () => FINAL }; };

  const result = await new ShieldBot().firewall('0xb', { chainId: 56 });

  assert.deepEqual(result, FINAL);
  assert.equal(requests.length, 1);
  assert.deepEqual(requests[0].headers, { 'Content-Type': 'application/json' });
});

test('each event restarts the finalTimeout clock', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const stream = streamingFetch();
  global.fetch = stream.fetch;
  const pending = new ShieldBot().firewall('0xb', { chainId: 56, finalTimeout: 1000, onFirst: () => {} });
  await flush();

  t.mock.timers.tick(900);
  stream.write(sse('first', FIRST));
  await flush();
  // 1800 ms after the request, but only 900 after the last event.
  t.mock.timers.tick(900);
  stream.write(sse('final', FINAL));
  stream.end();

  assert.deepEqual(await pending, FINAL);
});

test('a stream silent for finalTimeout after its last event is aborted', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const stream = streamingFetch();
  global.fetch = stream.fetch;
  // The client's own timeout does not apply to a streamed request; finalTimeout does.
  const pending = new ShieldBot({ timeout: 100 }).firewall('0xb', { chainId: 56, finalTimeout: 1000, onFirst: () => {} });
  let settled = false;
  pending.then(() => { settled = true; }, () => { settled = true; });
  await flush();
  stream.write(sse('first', FIRST));
  await flush();

  t.mock.timers.tick(999);
  await flush();
  assert.equal(settled, false);
  t.mock.timers.tick(1);

  await assert.rejects(pending, (error) => error instanceof ShieldBotError && error.code === 'TIMEOUT');
});
