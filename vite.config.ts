import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwind from "@tailwindcss/vite";

// Two roots, one config, selected by mode.
//
//   pnpm harness      → tests/harness, the component test page
//   pnpm build:ui     → web, the reference console, built into web/dist and embedded
//                       into the oarlockd binary
//
// Neither is a library build: the packages ship as TypeScript source and each consumer
// bundles them with their own toolchain.
export default defineConfig(({ mode }) => {
  if (mode === "harness") {
    return {
      root: "tests/harness",
      publicDir: false,
      server: { fs: { allow: [".."] }, port: 5178, strictPort: true },
      resolve: { preserveSymlinks: false },
    };
  }
  return {
    root: "web",
    plugins: [react(), tailwind()],
    // Relative, so the bundle works wherever the gateway mounts it.
    base: "./",
    build: {
      outDir: "dist",
      emptyOutDir: true,
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (id.includes("/node_modules/react") || id.includes("/node_modules/react-dom")) {
              return "react-vendor";
            }
            if (id.includes("/node_modules/@xterm/")) return "xterm";
          },
        },
      },
    },
    server: {
      fs: { allow: [".."] },
      port: 5179,
      strictPort: true,
      proxy: {
        "/api": "http://127.0.0.1:8443",
        "/ws": { target: "ws://127.0.0.1:8443", ws: true },
      },
    },
    resolve: { preserveSymlinks: false },
  };
});
