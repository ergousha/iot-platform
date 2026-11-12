import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The CSP (portal.tf) allows script-src 'self' and style-src 'self' only:
// no inline scripts or styles may end up in the build.
export default defineConfig({
  plugins: [react()],
  build: {
    target: "es2022",
    sourcemap: false,
    modulePreload: { polyfill: false }, // the polyfill is an inline script
    assetsInlineLimit: 0, // no data: URIs for assets
    chunkSizeWarningLimit: 800, // one ~180 KB gzipped bundle; loaded once per session
  },
  test: {
    environment: "node",
  },
});
