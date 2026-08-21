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
    build: { outDir: "dist", emptyOutDir: true },
    server: { fs: { allow: [".."] }, port: 5179, strictPort: true },
    resolve: { preserveSymlinks: false },
  };
});
