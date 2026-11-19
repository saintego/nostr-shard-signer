// The Buffer polyfill that Web3Auth needs (buffer@6, via
// vite-plugin-node-polyfills) doesn't know the "base64url" encoding. Evolu sees
// a global Buffer and uses it with "base64url" ("Unknown encoding: base64url").
// Teach that Buffer the encoding. Import this before Evolu.
import { Buffer as PolyBuffer } from 'buffer';

type B = typeof PolyBuffer & { __base64url?: true };
const targets = new Set<B>([PolyBuffer as B]);
const g = (globalThis as { Buffer?: B }).Buffer;
if (g) targets.add(g);

for (const Buf of targets) {
    if (Buf.__base64url) continue;
    Buf.__base64url = true;
    const from = Buf.from.bind(Buf) as (...a: unknown[]) => InstanceType<B>;
    (Buf as unknown as { from: unknown }).from = (value: unknown, enc?: unknown, ...rest: unknown[]) => {
        if (enc === 'base64url' && typeof value === 'string') {
            let s = value.replace(/-/g, '+').replace(/_/g, '/');
            while (s.length % 4) s += '=';
            return from(s, 'base64');
        }
        return from(value, enc, ...rest);
    };
    const toString = Buf.prototype.toString as (this: unknown, ...a: unknown[]) => string;
    Buf.prototype.toString = function (this: unknown, enc?: unknown, ...rest: unknown[]) {
        if (enc === 'base64url')
            return toString.call(this, 'base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        return toString.call(this, enc, ...rest);
    } as typeof Buf.prototype.toString;
}
