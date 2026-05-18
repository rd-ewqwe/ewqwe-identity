import { defineConfig } from "vite";
import tailwindcss from "tailwindcss";
import autoprefixer from "autoprefixer";
import * as path from "node:path";
import basicSsl from "@vitejs/plugin-basic-ssl";

// Shared proxy target for the Rust credential verifier.
// secure:false accepts the self-signed dev certificate on localhost:9443.
const credentialVerifierUrl =
  process.env["CREDENTIAL_VERIFIER_URL"] ?? "https://127.0.0.1:9443";

/**
 * Configure the http-proxy instance used by Vite.
 *
 * We only log request/response — we do NOT register an `error` handler
 * because Vite has its own built-in error handler that properly sends a
 * 502 response to the client when the upstream is unreachable.
 * Registering a second error handler that doesn't send a response would
 * conflict with Vite's handler and leave the client hanging.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function configureProxy(proxy: any): void {
  // Log request forwarding
  proxy.on("proxyReq", (_proxyReq: any, req: any) => {
    console.log(`[Vite] ${req.method} ${req.url} → credential_verifier`);
  });

  // Log responses and error bodies from the backend
  proxy.on("proxyRes", (proxyRes: any, req: any) => {
    const status = proxyRes.statusCode;
    console.log(`    → ${status}`);

    if (status >= 400) {
      // Collect and log the response body for server errors
      const chunks: Buffer[] = [];
      proxyRes.on("data", (chunk: Buffer) => chunks.push(chunk));
      proxyRes.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf-8");
        console.error(
          `[Vite] Upstream error ${status} on ${req.method} ${req.url}:`,
          body.slice(0, 2000),
        );
      });
    }
  });
  // Note: no `error` handler — Vite's built-in handler sends a 502 response.
}

export default defineConfig({
  root: ".",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  resolve: {
    alias: {
      // Resolve to the source TypeScript so Vite can transpile it directly.
      "@ewqwe/digital-identity": path.resolve(
        import.meta.dirname!,
        "../js-lib/ewqwe-digital-identity/src/lib.ts",
      ),
    },
  },
  server: {
    https: true,
    host: "0.0.0.0",
    port: 5174,
    proxy: {
      "/ewqwe_api": {
        target: credentialVerifierUrl,
        changeOrigin: true,
        secure: false,
        configure: configureProxy,
      },
    },
  },
  css: {
    postcss: {
      plugins: [
        tailwindcss as import("postcss").AcceptedPlugin,
        autoprefixer as import("postcss").AcceptedPlugin,
      ],
    },
  },
  plugins: [basicSsl()],
});
