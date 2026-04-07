import { defineConfig } from "npm:vite@^5.4.0";
import tailwindcss from "npm:tailwindcss@^3.4.0";
import autoprefixer from "npm:autoprefixer@^10.4.0";

export default defineConfig({
  root: ".",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    host: '0.0.0.0',
    port: 5174,
  },
  css: {
    postcss: {
      plugins: [
        tailwindcss as any,
        autoprefixer as any,
      ],
    },
  },
});
