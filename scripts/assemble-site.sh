#!/usr/bin/env bash
# Copy the built signer, bridge, portal and docs into the GitHub Pages layout.
# Used by the deploy and PR preview workflows and by scripts/local.sh.
# Run `npm run build --workspace=bunker` first.
#
# Usage: scripts/assemble-site.sh <out-dir>
#   <out-dir>/signer.html        → Vite-built React app (from bunker/dist/index.html)
#   <out-dir>/assets/            → Vite-hashed JS/CSS chunks
#   <out-dir>/nostr-bridge.js    → bridge script loaded by portal
#   <out-dir>/portal/index.html, <out-dir>/index.html → developer portal
#   <out-dir>/llms*.txt, <out-dir>/examples/ → docs for AI coding agents
set -euo pipefail
cd "$(dirname "$0")/.."

out=${1:?usage: scripts/assemble-site.sh <out-dir>}
mkdir -p "$out/portal"
cp nostr-bridge.js "$out/nostr-bridge.js"
cp bunker/dist/index.html "$out/signer.html"
cp -r bunker/dist/assets "$out/assets"
cp portal/index.html "$out/portal/index.html"
cp portal/index.html "$out/index.html"
cp llms.txt llms-full.txt "$out/"
cp -r examples "$out/examples"
