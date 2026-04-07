import { defineConfig } from "npm:vite@^5.4.0";
import tailwindcss from "npm:tailwindcss@^3.4.0";
import autoprefixer from "npm:autoprefixer@^10.4.0";
import * as path from "node:path";

export default defineConfig({
  root: ".",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  resolve: {
    alias: {
      "@ewqwe/digital-identity": path.resolve(
        import.meta.dirname!,
        "../js-lib/ewqwe-digital-identity/mod.ts",
      ),
    },
  },
  server: {
    host: "0.0.0.0",
    port: 5174,
    proxy: {
      "/api": {
        target: "http://localhost:5175",
        changeOrigin: true,
      },
    },
  },
  css: {
    postcss: {
      plugins: [tailwindcss as any, autoprefixer as any],
    },
  },
});
