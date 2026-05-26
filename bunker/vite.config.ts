import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { nodePolyfills } from "vite-plugin-node-polyfills";

// GitHub Pages serves the site under /nostr-shard-signer/
export default defineConfig({
  base: "/nostr-shard-signer/",
  plugins: [
    react(),
    nodePolyfills({
      // protocolImports: polyfill node:process, node:stream etc. used by
      // Web3Auth v10's internal auth-adapter streams (avoids nextTick errors)
      protocolImports: true,
      include: ["buffer", "process", "stream", "util", "events"],
      globals: { Buffer: true, process: true, global: true },
    }),
  ],
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
