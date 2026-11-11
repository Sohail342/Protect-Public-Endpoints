// sp.js — browser wrapper around the protection WASM.
//
//   <script src="/_sp/w/sp.js"></script>
//   const res = await SP.fetch('/api/rates');   // same shape as fetch()
//
// It fetches a challenge, loads the WASM variant the server names for the
// current epoch, lets it derive the session key and solve the proof of work,
// then signs every request and unseals sealed responses. It re-handshakes
// automatically when the token expires or the server rejects it.
(() => {
  const state = {
    base: '',          // origin of the protected API ('' = same origin)
    prefix: '/_sp/',
    api: null,         // exports of the currently active WASM variant
    token: '',
    exp: 0,
    wpow: 0,
    variants: new Map(), // wasm url -> api
    pending: null,
  };

  const abs = (p) => new URL(p, state.base || (typeof location !== 'undefined' ? location.href : undefined));

  async function loadRuntime() {
    if (globalThis.Go) return;
    await new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = abs(state.prefix + 'w/wasm_exec.js').href;
      s.onload = resolve;
      s.onerror = () => reject(new Error('sp: cannot load wasm runtime'));
      document.head.appendChild(s);
    });
  }

  async function loadVariant(url) {
    if (state.variants.has(url)) return state.variants.get(url);
    await loadRuntime();
    const bytes = await (await fetch(abs(url))).arrayBuffer();
    const go = new globalThis.Go();
    const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
    const api = await new Promise((resolve) => {
      globalThis.__sp_boot = resolve;
      go.run(instance); // keeps running; resolves only if the module exits
    });
    delete globalThis.__sp_boot;
    state.variants.set(url, api);
    return api;
  }

  async function handshake() {
    const ch = await (await fetch(abs(state.prefix + 'challenge'), { cache: 'no-store' })).json();
    const api = await loadVariant(ch.wasm);
    const h = api.handshake(ch.c, ch.seed, ch.prog, ch.diff, ch.now);
    if (!h) throw new Error('sp: handshake failed');
    const res = await fetch(abs(state.prefix + 'token'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ c: ch.c, n: h.n, env: h.env, proof: h.proof }),
    });
    if (!res.ok) throw new Error('sp: token refused (' + res.status + ')');
    const t = await res.json();
    state.api = api;
    state.token = t.t;
    state.exp = Date.now() + (t.exp - ch.now); // lifetime on the local clock
    state.wpow = ch.wpow;
  }

  function ensure() {
    if (state.api && Date.now() < state.exp - 3000) return Promise.resolve();
    if (!state.pending) state.pending = handshake().finally(() => { state.pending = null; });
    return state.pending;
  }

  function toBytes(body) {
    if (body == null) return new Uint8Array(0);
    if (typeof body === 'string') return new TextEncoder().encode(body);
    if (body instanceof Uint8Array) return body;
    if (body instanceof ArrayBuffer) return new Uint8Array(body);
    throw new Error('sp: body must be a string, Uint8Array or ArrayBuffer');
  }

  async function spFetch(input, init = {}, retried = false) {
    await ensure();
    const url = abs(input);
    const method = (init.method || 'GET').toUpperCase();
    const body = toBytes(init.body);
    const write = method !== 'GET' && method !== 'HEAD';
    const s = state.api.sign(method, url.pathname, url.search.slice(1), body, write ? state.wpow : 0);
    if (!s) throw new Error('sp: signing failed');

    const headers = new Headers(init.headers || {});
    headers.set('X-SP-Token', state.token);
    headers.set('X-SP-Ts', s.ts);
    headers.set('X-SP-Nonce', s.nonce);
    headers.set('X-SP-Sig', s.sig);
    if (s.pow) headers.set('X-SP-Pow', s.pow);

    const res = await fetch(url, { ...init, method, headers, body: body.length ? body : undefined });

    if (res.status === 403 && !retried) { // token expired or rotated away
      state.exp = 0;
      return spFetch(input, init, true);
    }
    if (res.headers.get('X-SP-Sealed') !== '1') return res;

    const plain = state.api.unseal(new Uint8Array(await res.arrayBuffer()), s.nonce);
    if (!plain) throw new Error('sp: could not unseal response');
    return new Response(plain, {
      status: res.status,
      headers: { 'Content-Type': res.headers.get('X-SP-Content-Type') || 'application/octet-stream' },
    });
  }

  globalThis.SP = {
    fetch: (input, init) => spFetch(input, init),
    configure: (opts) => Object.assign(state, opts),
  };
})();
