import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { nodePolyfills } from "vite-plugin-node-polyfills";
import stdLibBrowser from "node-stdlib-browser";
import type { Plugin } from "vite";

// Web3Auth v10 pre-bundles readable-stream and ships its own CJS→ESM process
// polyfill as a lazy factory (Kc/similar).  That factory returns the *module
// namespace* { default, process } rather than the process object itself, so
// `t = factory()` gives an object where `t.nextTick` is undefined even though
// `t.process.nextTick` exists.  This plugin finds that namespace construction
// in every output chunk and adds the missing `.nextTick` alias.
//
// NOTE: since the upgrade to Web3Auth v11 this pattern no longer occurs in the
// build output, so the plugin is currently a no-op (Web3Auth init verified
// working without it). Kept as a safety net; remove once social login has been
// confirmed working on v11 in production.
const patchProcessNs: Plugin = {
  name: "patch-process-namespace-nexttick",
  renderChunk(code: string) {
    // Pattern: ns.default=proc,ns.process=proc})(arg)),arg}
    // i.e. the last two lines of the IIFE that builds the module namespace and
    // the closing of the outer lazy-init wrapper.
    const fixed = code.replace(
      /(\w+)\.default=(\w+),\1\.process=\2\}\)\((\w+)\)\),\3\}/g,
      (_, ns, proc, arg) =>
        `${ns}.default=${proc},${ns}.process=${proc},${ns}.nextTick=${proc}.nextTick})(${arg})),${arg}}`,
    );
    if (fixed !== code) {
      return { code: fixed, map: null };
    }
    return null;
  },
};

// GitHub Pages serves the site under /nostr-shard-signer/
export default defineConfig({
  base: "/nostr-shard-signer/",
  plugins: [
    react(),
    nodePolyfills({
      // Still required on Web3Auth v11: its bundled connectors (MetaMask mobile,
      // Solana, WalletConnect) call the global `Buffer` without a typeof guard,
      // so the `Buffer`/`global` globals below must stay.
      //
      // protocolImports: polyfill node:process, node:stream etc. used by
      // Web3Auth v10's internal auth-adapter streams (avoids nextTick errors)
      protocolImports: true,
      include: ["buffer", "process", "stream", "util", "events"],
      // Don't inject a process module variable globally — readable-stream inside
      // Web3Auth uses its own embedded factory (Kc/similar) that bypasses
      // Rollup's inject; relying on globalThis.process from index.html is safer.
      globals: { Buffer: true, process: false, global: true },
    }),
    patchProcessNs,
  ],
  // readable-stream@4 (used by @web3auth/auth) does `require('process/')`.
  // In dev, the polyfill plugin's esbuild resolver maps that to
  // `.../proxy/process/`, which is a directory, and dependency optimization
  // fails. Resolve the trailing-slash form to the same shim file first.
  // (Production builds go through Rollup and are unaffected.)
  optimizeDeps: {
    esbuildOptions: {
      plugins: [
        {
          name: "process-trailing-slash",
          setup(build) {
            build.onResolve({ filter: /^process\/$/ }, () => ({
              path: `${stdLibBrowser.process}.js`,
            }));
          },
        },
      ],
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
