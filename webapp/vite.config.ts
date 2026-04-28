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
      // Resolve to the pre-built ESM dist so that Chrome's native module loader
      // always receives a valid JavaScript file (text/javascript MIME type).
      // Serving a raw .ts file via the alias causes the crbug/1173575 deprecation
      // warning: "non-JS module files deprecated".
      "@ewqwe/digital-identity": path.resolve(
        import.meta.dirname!,
        "../js-lib/ewqwe-digital-identity/src/lib.ts",
      ),
    },
  },
  server: {
    host: "0.0.0.0",
    port: 5174,
    proxy: {
      "/ewqwe_api": {
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
