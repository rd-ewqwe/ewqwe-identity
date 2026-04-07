import { defineConfig } from "vite";
import tailwindcss from "tailwindcss";
import autoprefixer from "autoprefixer";
import * as path from "node:path";
import basicSsl from "@vitejs/plugin-basic-ssl";
import postcss from "postcss";

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
        timeout: 30000,
        proxyTimeout: 30000,
      },
    },
  },
  css: {
    postcss: {
      plugins: [
        tailwindcss as postcss.AcceptedPlugin,
        autoprefixer as postcss.AcceptedPlugin,
      ],
    },
  },
  plugins: [
    basicSsl({
      /** name of certification */
      name: "test",
      /** custom trust domains */
      domains: ["*.custom.com"],
      /** custom certification directory */
      certDir: "/Users/.../.devServer/cert",
    }),
  ],
});
