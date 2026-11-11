// Three things a scraper tries first, run against the demo server:
//
//   node example/attacker/attack.mjs http://localhost:8080 dist
//
// 1. call the API directly, 2. forge the protection headers, 3. lift the
// site's own WASM and run it outside a browser. Each should be refused.
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [base = 'http://localhost:8080', dist = 'dist'] = process.argv.slice(2);
const show = (name, ok, detail) => console.log(`${ok ? 'BLOCKED ' : 'GOT IN  '} ${name}: ${detail}`);

// 1. direct call, no headers
{
  const res = await fetch(base + '/api/rates');
  show('direct API call', res.status === 403, `HTTP ${res.status}`);
}

// 2. forged headers: right shape, no knowledge of the server secret
{
  const fake = Buffer.from(JSON.stringify({ t: 'k', e: 1, s: 'AAAA', x: Date.now() + 60000, b: 'x' })).toString('base64url');
  const res = await fetch(base + '/api/rates', {
    headers: {
      'X-SP-Token': `k1.${fake}.${'A'.repeat(43)}`,
      'X-SP-Ts': String(Date.now()),
      'X-SP-Nonce': 'a'.repeat(24),
      'X-SP-Sig': 'A'.repeat(43),
    },
  });
  show('forged token', res.status === 403, `HTTP ${res.status}`);
}

// 3. lift the real client (sp.js + WASM) and run it under Node
{
  await import(pathToFileURL(path.resolve(dist, 'wasm_exec.js')).href);
  await import(pathToFileURL(path.resolve(dist, 'sp.js')).href);
  globalThis.SP.configure({ base });
  try {
    const res = await globalThis.SP.fetch('/api/rates');
    show('lifted WASM in Node', false, `HTTP ${res.status} ${await res.text()}`);
  } catch (e) {
    show('lifted WASM in Node', true, e.message);
  }
}
setTimeout(() => process.exit(0), 200);
