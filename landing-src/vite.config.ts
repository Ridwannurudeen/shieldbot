import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../landing",
    emptyOutDir: true,
    // Terser, three passes: about 4 KB smaller than esbuild's minifier, which keeps the bundle inside its 320,000 B budget.
    minify: "terser",
    terserOptions: { compress: { passes: 3, ecma: 2020 }, format: { comments: false } },
  },
  server: {
    proxy: {
      "/api": "http://localhost:8000",
    },
  },
});
