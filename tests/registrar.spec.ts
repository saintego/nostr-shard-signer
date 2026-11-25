// The registrar Worker (#68): signed registration, failing closed while
// Web3Auth's settings can't be read, and the project owner's registrant
// markers. Runs the Worker's fetch handler in Node, with KV, relays and
// Web3Auth's configuration faked.
import { expect, test } from '@playwright/test';
import { finalizeEvent, generateSecretKey, getPublicKey, nip19 } from 'nostr-tools';
import worker from '../registrar/registrar-worker.js';

const CLIENT = 'client-abc';
const SIGNER = 'https://signer.example';
const SITE = 'https://app.example.com';

function kv() {
  const store = new Map<string, string>();
  return {
    get: async (k: string) => store.get(k) ?? null,
    put: async (k: string, v: string) => void store.set(k, v),
    delete: async (k: string) => void store.delete(k),
    list: async ({ prefix = '' } = {}) => ({
      keys: [...store.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })),
      list_complete: true,
    }),
  };
}

const env = (extra: Record<string, unknown> = {}) => ({
  ROOT_PRIVATE_KEY_HEX: 'ab'.repeat(32),
  REGISTRY_KV: kv(),
  CHALLENGES_KV: kv(),
  RELAY_URLS: 'wss://relay.test',
  SIGNER_ORIGIN: SIGNER,
  ...extra,
});

/** Web3Auth's configuration: the allowlist, or an outage. */
let allowlist: string[] | 'down' = [];
const realFetch = globalThis.fetch;
const RealWebSocket = globalThis.WebSocket;

test.beforeEach(() => {
  allowlist = [SIGNER, SITE];
  globalThis.fetch = (async () =>
    allowlist === 'down'
      ? new Response('busy', { status: 502 })
      : new Response(JSON.stringify({ whitelist: { urls: allowlist } }))) as typeof fetch;
  // A relay that accepts every event.
  globalThis.WebSocket = class {
    private handlers: Record<string, ((e: { data?: string }) => void)[]> = {};
    constructor() {
      setTimeout(() => this.emit('open', {}), 0);
    }
    addEventListener(type: string, fn: (e: { data?: string }) => void) {
      this.handlers[type] = [...(this.handlers[type] ?? []), fn];
    }
    emit(type: string, e: { data?: string }) {
      for (const fn of this.handlers[type] ?? []) fn(e);
    }
    send(raw: string) {
      const [, event] = JSON.parse(raw);
      setTimeout(
        () => this.emit('message', { data: JSON.stringify(['OK', event.id, true, '']) }),
        0
      );
    }
    close() {}
  } as unknown as typeof WebSocket;
});
test.afterEach(() => {
  globalThis.fetch = realFetch;
  globalThis.WebSocket = RealWebSocket;
});

type Env = ReturnType<typeof env>;
const post = async (e: Env, path: string, body: unknown) => {
  const res = await worker.fetch(
    new Request(`https://registrar.test${path}`, { method: 'POST', body: JSON.stringify(body) }),
    e,
    {}
  );
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
};

const user = () => {
  const sk = generateSecretKey();
  return { sk, npub: nip19.npubEncode(getPublicKey(sk)), hex: getPublicKey(sk) };
};
const proof = (sk: Uint8Array, nonce: string) =>
  finalizeEvent(
    { kind: 27235, created_at: Math.floor(Date.now() / 1000), tags: [], content: nonce },
    sk
  );

/** Both phases of /register, signed by `signer` (the npub's own key unless given). */
async function register(e: Env, who: ReturnType<typeof user>, signer = who.sk) {
  const first = await post(e, '/register', { clientId: CLIENT, npub: who.npub, domain: SITE });
  if (first.status !== 200 || !first.body.nonce) return first;
  const nonce = first.body.nonce as string;
  return post(e, '/register', {
    clientId: CLIENT,
    npub: who.npub,
    domain: SITE,
    nonce,
    signedEvent: proof(signer, nonce),
  });
}

test('/register without a signature only returns a challenge; nothing is claimed', async () => {
  const e = env();
  const a = user();
  const first = await post(e, '/register', { clientId: CLIENT, npub: a.npub, domain: SITE });
  expect(first.status).toBe(200);
  expect(first.body.nonce).toMatch(/^[0-9a-f]{64}$/);
  expect(await e.REGISTRY_KV.get(`claim:${CLIENT}`)).toBeNull();
});

test('/register with a valid signature claims the clientId (201)', async () => {
  const e = env();
  const a = user();
  const done = await register(e, a);
  expect(done.status).toBe(201);
  expect(JSON.parse((await e.REGISTRY_KV.get(`claim:${CLIENT}`)) ?? '{}').registrantHex).toBe(
    a.hex
  );
});

test('/register signed by another key is refused (403)', async () => {
  const e = env();
  const done = await register(e, user(), user().sk);
  expect(done.status).toBe(403);
  expect(await e.REGISTRY_KV.get(`claim:${CLIENT}`)).toBeNull();
});

test("Web3Auth's settings unreadable: 503; with ALLOW_UNCHECKED, accepted with a note", async () => {
  allowlist = 'down';
  const closed = await register(env(), user());
  expect(closed.status).toBe(503);
  const open = await register(env({ ALLOW_UNCHECKED: 'true' }), user());
  expect(open.status).toBe(201);
  expect(String(open.body.note)).toContain('ALLOW_UNCHECKED');
});

test("another npub's claim is refused (409) unless the project owner names it in the allowlist", async () => {
  const e = env();
  const a = user();
  const b = user();
  expect((await register(e, a)).status).toBe(201);
  const refused = await register(e, b);
  expect(refused.status).toBe(409);
  expect(String(refused.body.error)).toContain('.nostr-registrant.invalid');
  // The project owner adds B's marker: B takes the claim over.
  allowlist = [SIGNER, SITE, `https://${b.npub}.nostr-registrant.invalid`];
  const taken = await register(e, b);
  expect(taken.status).toBe(201);
  expect(JSON.parse((await e.REGISTRY_KV.get(`claim:${CLIENT}`)) ?? '{}').registrantHex).toBe(
    b.hex
  );
  const event = JSON.parse((await e.REGISTRY_KV.get(`event:${CLIENT}`)) ?? '{}');
  expect(event.tags.find((t: string[]) => t[0] === 'p')?.[1]).toBe(b.hex);
});

test('with registrant markers, an unnamed npub cannot claim an unclaimed clientId', async () => {
  const named = user();
  allowlist = [SIGNER, SITE, `https://${named.npub}.nostr-registrant.invalid`];
  expect((await register(env(), user())).status).toBe(403);
  expect((await register(env(), named)).status).toBe(201);
});

test('/update still needs the registrant’s signature', async () => {
  const e = env();
  const a = user();
  await register(e, a);
  const first = await post(e, '/update', { clientId: CLIENT, npub: a.npub });
  const nonce = first.body.nonce as string;
  const bad = await post(e, '/update', {
    clientId: CLIENT,
    nonce,
    domains: [SITE],
    signedEvent: proof(user().sk, nonce),
  });
  expect(bad.status).toBe(403);
  const again = await post(e, '/update', { clientId: CLIENT, npub: a.npub });
  const good = await post(e, '/update', {
    clientId: CLIENT,
    nonce: again.body.nonce,
    domains: [SITE],
    signedEvent: proof(a.sk, again.body.nonce as string),
  });
  expect(good.status).toBe(200);
});
