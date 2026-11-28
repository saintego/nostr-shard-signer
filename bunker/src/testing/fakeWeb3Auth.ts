// A stand-in for @web3auth/modal in the test build only (VITE_FAKE_W3A=1,
// vite.config.ts), so the whole sign-in runs in Playwright (#127). It has the
// surface the signer uses, and draws its panel as real DOM in
// #w3a-parent-container, positioned like Web3Auth's (an inline
// `position: relative` container at the end of the body), so the widget's and
// the window's layout and taps are tested as they are.
//
// The login it returns: a fixed key per provider, or the one a test sets with
// localStorage 'fake-w3a-user' (a 64-hex key, on the signer's origin).

type Provider = string;

export const WEB3AUTH_NETWORK = {
  SAPPHIRE_MAINNET: 'sapphire_mainnet',
  SAPPHIRE_DEVNET: 'sapphire_devnet',
} as const;

export const WALLET_CONNECTORS = {
  AUTH: 'auth',
  WALLET_CONNECT_V2: 'wallet-connect-v2',
  METAMASK: 'metamask',
  COINBASE: 'coinbase',
} as const;

export type AuthLoginParams = { authConnection?: string };

export const authConnector = (settings: unknown) => ({ name: 'auth', settings });

const KEYS: Record<Provider, string> = {
  google: '1a'.repeat(32),
  twitter: '2b'.repeat(32),
  facebook: '3c'.repeat(32),
  apple: '4d'.repeat(32),
};

const keyFor = (provider: Provider) => {
  try {
    const set = localStorage.getItem('fake-w3a-user');
    if (set && /^[0-9a-f]{64}$/.test(set)) return set;
  } catch {
    // no storage: the provider's key
  }
  return KEYS[provider] ?? KEYS.google;
};

const PANEL_PROVIDERS: Provider[] = ['google', 'twitter', 'facebook'];

/**
 * A class like Web3Auth's (the signer calls its methods); test code only.
 * Mutable fields mirror the library's own state.
 */
export class Web3Auth {
  connected = false;
  status = 'not_ready';
  cachedConnector: string | null = null;
  connectedConnectorName: string | null = null;
  private provider: Provider | null = null;
  private listeners = new Map<string, Set<(...a: unknown[]) => void>>();
  private closePanel: ((provider: Provider | null) => void) | null = null;

  constructor(readonly options: unknown) {}

  /** Like Web3Auth's, which loads its project config: a test may set 'fake-w3a-init-ms'. */
  async init() {
    let ms = 0;
    try {
      ms = Number(localStorage.getItem('fake-w3a-init-ms') ?? 0);
    } catch {
      // no storage: instant
    }
    if (ms > 0) await new Promise((r) => setTimeout(r, ms));
    this.status = 'ready';
  }

  /** Web3Auth's panel: resolves with the connection, or null when it's closed. */
  async connect() {
    const chosen = await new Promise<Provider | null>((resolve) => {
      this.closePanel = resolve;
      this.drawPanel();
    });
    this.removePanel();
    if (!chosen) return null;
    return this.signIn(chosen);
  }

  async connectTo(_connector: string, params: AuthLoginParams) {
    return this.signIn(params.authConnection ?? 'google');
  }

  get connection() {
    if (!this.connected || !this.provider) return null;
    const key = keyFor(this.provider);
    // A proxy whose `request` reads `this`, like Web3Auth's (#102).
    const proxy = {
      provider: {
        request: async ({ method }: { method: string }) => (method === 'private_key' ? key : null),
      },
      request(
        this: { provider: { request: (a: { method: string }) => Promise<unknown> } },
        a: { method: string }
      ) {
        return this.provider.request(a);
      },
    };
    return { ethereumProvider: proxy };
  }

  async getUserInfo() {
    const p = this.provider ?? 'google';
    return {
      email: `alice@${p}.example`,
      name: 'Alice',
      profileImage: '',
      verifierId: `alice@${p}.example`,
      authConnection: p,
    };
  }

  async logout() {
    this.connected = false;
    this.provider = null;
  }

  get loginModal() {
    return { closeModal: () => this.closePanel?.(null) };
  }

  on(event: string, fn: (...a: unknown[]) => void) {
    const set = this.listeners.get(event) ?? new Set();
    set.add(fn);
    this.listeners.set(event, set);
  }
  once(event: string, fn: (...a: unknown[]) => void) {
    this.on(event, fn);
  }
  removeListener(event: string, fn: (...a: unknown[]) => void) {
    this.listeners.get(event)?.delete(fn);
  }

  private signIn(provider: Provider) {
    this.provider = provider;
    this.connected = true;
    this.status = 'connected';
    for (const fn of this.listeners.get('connected') ?? []) fn();
    return this.connection;
  }

  private drawPanel() {
    let parent = document.getElementById('w3a-parent-container');
    if (!parent) {
      parent = document.createElement('section');
      parent.id = 'w3a-parent-container';
      parent.style.position = 'relative';
      document.body.append(parent);
    }
    const sheet = document.createElement('div');
    sheet.className = 'w3a-modal-container';
    sheet.setAttribute('role', 'dialog');
    sheet.setAttribute('aria-label', 'Web3Auth sign-in');
    // Sized like Web3Auth's sheet, at the bottom of its container, as Web3Auth
    // lays it out (the widget positions the container).
    sheet.style.cssText =
      'position:absolute;left:0;right:0;bottom:0;height:420px;background:white;padding:24px;box-sizing:border-box;';
    const title = document.createElement('h2');
    title.textContent = 'Sign in';
    sheet.append(title);
    for (const p of PANEL_PROVIDERS) {
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = `Fake ${p}`;
      b.onclick = () => this.closePanel?.(p);
      sheet.append(b);
    }
    const close = document.createElement('button');
    close.type = 'button';
    close.textContent = 'Close panel';
    close.onclick = () => this.closePanel?.(null);
    sheet.append(close);
    parent.replaceChildren(sheet);
  }

  private removePanel() {
    this.closePanel = null;
    document.getElementById('w3a-parent-container')?.replaceChildren();
  }
}
