import { defineConfig } from "vite";
import mkcert from "vite-plugin-mkcert";

/**
 * Strip the `Secure` attribute from all `Set-Cookie` response headers so that
 * browsers accept session cookies when the Vite dev server is reached over
 * plain HTTP (e.g. from a LAN address like 192.168.x.x:5175).
 * The backend runs on HTTPS and therefore stamps every cookie with `Secure`;
 * browsers silently discard such cookies when the page itself is HTTP.
 */
function stripSecureCookie(proxyRes: {
  headers: Record<string, string | string[] | undefined>;
}) {
  const cookies = proxyRes.headers["set-cookie"] as string[] | undefined;
  if (!cookies) return;
  proxyRes.headers["set-cookie"] = cookies.map((c) =>
    c.replace(/;\s*Secure/gi, ""),
  );
}

// Shared proxy target for all backend routes.
// secure:false accepts the self-signed dev certificate on localhost:9443.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const backendProxy = {
  target: "https://192.168.1.90:9443",
  changeOrigin: true,
  secure: false,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  configure(proxy: any) {
    proxy.on("proxyRes", stripSecureCookie);
  },
};

export default defineConfig({
  root: ".",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    allowedHosts: true,
    host: "0.0.0.0",
    port: 9888,
    proxy: {
      "/api": backendProxy,
      "/ewqwe_api": backendProxy,
      "/.well-known": backendProxy,
      "/version": backendProxy,
    },
  },
  // plugins: [mkcert()],
});
