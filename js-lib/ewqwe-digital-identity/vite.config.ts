import { defineConfig } from "vite";
import { resolve } from "path";

export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, "src/lib.ts"),
      name: "@ewqwe/digital-identity",
      // Produces dist/index.mjs (ESM) and dist/index.cjs (CJS) matching package.json#exports.
      // Chrome's native ES module loader requires the response to have a valid JS MIME type;
      // serving compiled .mjs (not raw .ts) eliminates the crbug/1173575 deprecation warning.
      fileName: (format) => `index.${format === "es" ? "mjs" : "cjs"}`,
      formats: ["es", "cjs"],
    },
    rollupOptions: {
      output: {
        exports: "named",
      },
    },
    // Target modern browsers and Node >=18 for ESM/async support, avoid legacy transforms.
    target: ["es2022", "node18"],
    sourcemap: true,
    outDir: "dist",
  },
  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
    },
  },
});
