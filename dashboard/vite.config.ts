import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Relative base so the same build works from nginx at / and from GitHub Pages at /unhook/.
export default defineConfig({
  base: "./",
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:8000",
      "/healthz": "http://localhost:8000",
    },
  },
  build: { target: "es2022", sourcemap: false, chunkSizeWarningLimit: 600 },
});
