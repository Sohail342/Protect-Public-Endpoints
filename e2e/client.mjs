// Drives the real sp.js + WASM under Node against a test server.
//   node client.mjs <base-url> <dist-dir>
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [base, dist] = process.argv.slice(2);
await import(pathToFileURL(path.resolve(dist, 'wasm_exec.js')).href);
await import(pathToFileURL(path.resolve(dist, 'sp.js')).href);
globalThis.SP.configure({ base });

const t0 = performance.now();
const r1 = await globalThis.SP.fetch('/api/data?x=1');
const data = await r1.json();
const t1 = performance.now();
const r2 = await globalThis.SP.fetch('/api/form', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ hello: 'world' }),
});
const form = await r2.text();
const t2 = performance.now();
const r3 = await globalThis.SP.fetch('/api/data?x=2');
await r3.json();
const t3 = performance.now();

console.log(JSON.stringify({
  s1: r1.status, data, s2: r2.status, form,
  firstMs: Math.round(t1 - t0), writeMs: Math.round(t2 - t1), readMs: Math.round(t3 - t2),
}));
// The WASM instance keeps the event loop alive, so exit explicitly — after a
// short pause, because Node on Windows can abort if it exits mid-socket-close.
setTimeout(() => process.exit(0), 200);
