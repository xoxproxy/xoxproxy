import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Dev server proxies the API to the local Go control plane; in production
// the built assets are embedded in the binary and served same-origin.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  define: {
    // Release tag of the Go binary embedding this build (Makefile injects
    // the value; see the web target).
    __APP_VERSION__: JSON.stringify(process.env.APP_VERSION ?? "dev"),
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8080",
      "/health": "http://127.0.0.1:8080",
    },
  },
  build: {
    sourcemap: false,
  },
});
