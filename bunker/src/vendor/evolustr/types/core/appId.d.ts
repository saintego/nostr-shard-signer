import { type EvolustrError, type Result } from "./result.ts";
/**
 * App identity from a page origin (SPEC §3.3). On a known nsite gateway,
 * `<npub>.<gateway>` maps to `nsite:<npub>` so every known gateway shares one vault.
 *
 * Only `https:` origins, and `http:` on localhost for development, are accepted:
 * a network attacker could otherwise serve a page on `http://app.example` and get
 * that app's keys (#30). Anything that isn't a valid origin is an error, never
 * passed through, because app ids end up in AADs and d-tags.
 */
export declare const appIdFromOrigin: (origin: string, knownNsiteGateways?: ReadonlyArray<string>) => Result<string, EvolustrError>;
//# sourceMappingURL=appId.d.ts.map