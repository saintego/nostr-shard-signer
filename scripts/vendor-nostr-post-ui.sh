#!/usr/bin/env bash
# Copy the visual language of nostr-post (@nostr-post/ui: --np-* tokens and the
# np-* primitives) into bunker/src/vendor/nostr-post-ui/, until the package is
# on npm. Only the framework-free CSS is used: the signer is React, and pages
# can't restyle it (see AGENTS.md, Styling).
#
# Usage: scripts/vendor-nostr-post-ui.sh <path-to-nostr-post-checkout>
#   No install needed in the checkout: the CSS is generated from its token data
#   with this repo's esbuild.
set -euo pipefail
cd "$(dirname "$0")/.."
repo=$(cd "${1:?usage: scripts/vendor-nostr-post-ui.sh <path-to-nostr-post>}" && pwd)
src="$repo/packages/ui/src"
out=bunker/src/vendor/nostr-post-ui

rm -rf "$out"
mkdir -p "$out"
tmp=$(mktemp -d)
npx esbuild --bundle --format=esm --platform=node --log-level=warning --outfile="$tmp/css.mjs" \
  --sourcefile=entry.ts --loader=ts <<TS
export { tokensCss } from "$src/tokensCss";
export { uiCss } from "$src/uiCss";
TS
node --input-type=module -e "
import { writeFileSync } from 'node:fs';
const { tokensCss, uiCss } = await import('$tmp/css.mjs');
const header = '/* @nostr-post/ui, vendored by scripts/vendor-nostr-post-ui.sh: do not edit */\n';
writeFileSync('$out/tokens.css', header + tokensCss());
writeFileSync('$out/ui.css', header + uiCss());
"
cat > "$out/VERSION" <<TXT
saintego/nostr-post $(git -C "$repo" rev-parse HEAD)
packages/ui $(node -p "require('$repo/packages/ui/package.json').version")
TXT
cp "$repo/packages/ui/README.md" "$out/README.md"
echo "vendored into $out:"; ls "$out"
