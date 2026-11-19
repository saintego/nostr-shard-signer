// Small DOM helpers shared by the check pages (#73, "Checks before building").

export const params = new URLSearchParams(location.search);
export const role = (params.get('role') ?? 'top') as 'top' | 'frame' | 'tab';
export const BASE = location.pathname.replace(/[^/]*$/, ''); // …/nostr-shard-signer/

export const app = document.getElementById('app')!;

export function h<K extends keyof HTMLElementTagNameMap>(
    tag: K,
    props: Partial<Omit<HTMLElementTagNameMap[K], 'style'>> & { style?: string } = {},
    ...children: (Node | string | null | undefined)[]
): HTMLElementTagNameMap[K] {
    const el = document.createElement(tag);
    const { style, ...rest } = props;
    Object.assign(el, rest);
    if (style) el.setAttribute('style', style);
    for (const c of children) if (c !== null && c !== undefined) el.append(c);
    return el;
}

export const button = (label: string, onclick: () => unknown) =>
    h('button', { textContent: label, onclick: () => void onclick() });

/** The other origin used for cross-site checks: GitHub Pages ↔ the Cloudflare PR preview. */
export function otherOrigin(): string {
    const fromParam = params.get('other');
    if (fromParam) return fromParam.replace(/\/$/, '');
    try {
        const saved = localStorage.getItem('checks_other_origin');
        if (saved) return saved;
    } catch (_) { /* storage blocked */ }
    return location.hostname === 'saintego.github.io'
        ? 'https://preview.nostr-shard-signer.pages.dev'
        : 'https://saintego.github.io';
}

export function setOtherOrigin(origin: string): void {
    try { localStorage.setItem('checks_other_origin', origin.replace(/\/$/, '')); } catch (_) { /* ignore */ }
}

/** URL of this check page on another origin (same path), with extra params. */
export function pageUrl(origin: string, extra: Record<string, string>): string {
    const u = new URL(origin + location.pathname);
    for (const [k, v] of Object.entries(extra)) u.searchParams.set(k, v);
    return u.toString();
}

export function browserName(): string {
    const ua = navigator.userAgent;
    const safari = ua.match(/Version\/([\d.]+).*Safari/);
    const m =
        ua.match(/(Firefox|FxiOS)\/(\d+)/) ?? ua.match(/(Edg)\/(\d+)/) ?? ua.match(/(Chrome|CriOS)\/(\d+)/) ??
        (safari ? [safari[0], 'Safari', safari[1]] : null);
    const os = /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS X/.test(ua) ? 'macOS'
        : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : '?';
    return m ? `${m[1]} ${m[2]} on ${os}` : `${ua.slice(0, 60)} on ${os}`;
}

export type Status = 'pass' | 'fail' | 'info' | 'warn';
const ICON: Record<Status, string> = { pass: '✅', fail: '❌', info: 'ℹ️', warn: '⚠️' };

/** A result log for one check, with a "Copy report" button for the results issue. */
export class Report {
    readonly lines: { status: Status; text: string }[] = [];
    readonly el = h('ul', { className: 'log' });

    constructor(readonly check: string, readonly where: string = role) { }

    add(status: Status, text: string): void {
        this.lines.push({ status, text });
        this.el.append(h('li', { className: status }, `${ICON[status]} ${text}`));
        console.log(`[${this.check}] ${status}: ${text}`);
    }
    pass(t: string) { this.add('pass', t); }
    fail(t: string) { this.add('fail', t); }
    info(t: string) { this.add('info', t); }
    warn(t: string) { this.add('warn', t); }

    markdown(): string {
        const head = `**${this.check}** — ${browserName()} — ${this.where} on \`${location.origin}\` — ${new Date().toISOString()}`;
        return [head, '', ...this.lines.map(l => `- ${ICON[l.status]} ${l.text}`)].join('\n');
    }

    /** The log plus Copy/Clear buttons. */
    view(): HTMLElement {
        const copy = button('Copy report', async () => {
            const text = this.markdown();
            try {
                await navigator.clipboard.writeText(text);
                copy.textContent = 'Copied';
            } catch (_) {
                // Clipboard blocked (e.g. in an iframe): show it to copy by hand.
                const ta = h('textarea', { value: text, rows: 10, style: 'width:100%' });
                this.el.after(ta);
                ta.select();
            }
            setTimeout(() => (copy.textContent = 'Copy report'), 1500);
        });
        return h('section', {}, this.el, h('div', {}, copy));
    }
}

export const hex = (b: Uint8Array) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
export const fromHex = (s: string) => new Uint8Array(s.match(/../g)!.map(x => parseInt(x, 16)));
export const randomHex = (n = 32) => hex(crypto.getRandomValues(new Uint8Array(n)));

export function age(ms: number): string {
    const s = Math.round(ms / 1000);
    if (s < 120) return `${s} s`;
    if (s < 7200) return `${Math.round(s / 60)} min`;
    if (s < 172800) return `${Math.round(s / 3600)} h`;
    return `${(s / 86400).toFixed(1)} days`;
}

/** An iframe of this page on another origin, in the role "frame". */
export function crossFrame(check: string, origin: string, allow = ''): HTMLIFrameElement {
    return h('iframe', {
        src: pageUrl(origin, { c: check, role: 'frame' }),
        allow,
        style: 'width:100%;height:420px;border:2px dashed #888;border-radius:6px',
    });
}

/** Header with the other-origin setting, shown on top-level host pages. */
export function originPicker(onChange: () => void): HTMLElement {
    const input = h('input', { value: otherOrigin(), size: 50 });
    return h('p', {},
        'Other origin (the iframe or second site): ', input, ' ',
        button('Use', () => { setOtherOrigin(input.value); onChange(); }),
    );
}
