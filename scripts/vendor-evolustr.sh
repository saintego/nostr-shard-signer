#!/usr/bin/env bash
# Bundle @evolustr/signer (and the parts of @evolustr/core it needs) into
# bunker/src/vendor/evolustr/, until the packages are on npm (evolustr #21).
#
# Usage: scripts/vendor-evolustr.sh <path-to-evolustr-checkout>
#   The checkout needs `npm ci` first. The script builds core and signer,
#   bundles them with nostr-tools left external (the signer already depends
#   on it), copies their type declarations and records the commit.
set -euo pipefail
cd "$(dirname "$0")/.."
repo=$(cd "${1:?usage: scripts/vendor-evolustr.sh <path-to-evolustr>}" && pwd)
out=bunker/src/vendor/evolustr

(cd "$repo" && npm run build -w @evolustr/core -w @evolustr/signer >/dev/null)

rm -rf "$out"
mkdir -p "$out/types"
cp -r "$repo/packages/core/dist" "$out/types/core"
cp -r "$repo/packages/signer/dist" "$out/types/signer"
find "$out/types" -type f ! -name '*.d.ts' -delete
# The signer's declarations import "@evolustr/core": point them at the copy.
find "$out/types/signer" -name '*.d.ts' -exec sed -i 's#"@evolustr/core"#"../core/index.js"#' {} +

entry=$(mktemp -d)/entry.js
cat > "$entry" <<JS
export { createEvolustrSigner, isProtectedEvent } from "$repo/packages/signer/dist/index.js";
export { poolRelays, webauthnPasskeys, toBase64Url, fromBase64Url } from "$repo/packages/core/dist/index.js";
JS
npx esbuild "$entry" --bundle --format=esm --platform=browser --target=es2021 \
  --external:'nostr-tools' --external:'nostr-tools/*' \
  --alias:@evolustr/core="$repo/packages/core/dist/index.js" \
  --legal-comments=none --log-level=warning --outfile="$out/evolustr.js"

cat > "$out/evolustr.d.ts" <<'TS'
export { createEvolustrSigner, isProtectedEvent } from "./types/signer/index.js";
export type { Caller, ConfirmRequest, EvolustrSigner, SignerHost, Capabilities } from "./types/signer/index.js";
export { poolRelays, webauthnPasskeys, toBase64Url, fromBase64Url } from "./types/core/index.js";
export type { Bytes, Passkeys, PasskeyResult, CreatedPasskey, NostrEvent, UnsignedEvent } from "./types/core/index.js";
TS

commit=$(git -C "$repo" rev-parse HEAD)
printf '@evolustr/signer bundled from https://github.com/saintego/evolustr at %s\nRegenerate with scripts/vendor-evolustr.sh; do not edit by hand.\n' "$commit" > "$out/VERSION"
echo "Vendored evolustr $commit into $out"
