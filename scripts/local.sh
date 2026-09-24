#!/usr/bin/env bash
# Build and serve the GitHub Pages layout locally, for testing the portal and
# signer together at http://localhost:3000/nostr-shard-signer/portal/
#
# The signer is built with VITE_LOCAL_TEST=true, which skips the NIP-33 registry
# check for localhost parents (the registrar refuses localhost domains).
# Never deploy this build.
set -euo pipefail
cd "$(dirname "$0")/.."

VITE_LOCAL_TEST=true npm run build --workspace=bunker

# Same layout as the "Assemble Pages artifact" step in .github/workflows/deploy.yml,
# nested under /nostr-shard-signer/ to match the Pages URL.
root=.local-site
site=$root/nostr-shard-signer
rm -rf "$root"
mkdir -p "$site/portal"
cp nostr-bridge.js "$site/nostr-bridge.js"
cp bunker/dist/index.html "$site/signer.html"
cp -r bunker/dist/assets "$site/assets"
cp portal/index.html "$site/portal/index.html"
cp portal/index.html "$site/index.html"
# Serve portal/ as its index.html, but keep signer.html as-is: serve's clean-URL
# redirect to /signer would drop the query string the bridge passes.
echo '{ "cleanUrls": ["!**/signer.html"] }' > "$root/serve.json"

echo
echo "Portal: http://localhost:3000/nostr-shard-signer/portal/"
echo
npx serve "$root" -l 3000
