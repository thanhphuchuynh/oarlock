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
  if (mode === "landing") {
    // The marketing sheet. Static HTML and CSS, no framework: it inherits the toolchain
    // rather than the runtime, and nothing it ships is embedded in the gateway binary.
    return {
      root: "landing",
      base: "./",
      build: { outDir: "dist", emptyOutDir: true },
      // 5180 serves the source with live reload; 5181 serves the built output, which is
      // what a host would serve. Both strict on purpose: a silent fall back to the next
      // free port means the tab already open is showing the previous build, and nothing
      // on screen says so.
      server: { port: 5180, strictPort: true },
      preview: { port: 5181, strictPort: true },
    };
  }
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
    // Absolute, and it has to be. A relative base resolves against the *document's*
    // directory, so it works only while every route is a single segment: on `/ui/` the
    // browser asks for `/ui/assets/…`, but on `/ui/s/sess_x` it asks for
    // `/ui/s/assets/…`, which `ui.Handler`'s SPA fallback answers with index.html — a
    // 200 of `text/html` where a script was expected, so the page renders blank and
    // nothing in the network log looks like an error.
    //
    // This used to say "relative, so the bundle works wherever the gateway mounts it".
    // That stopped being true when the console gained routes with depth. The mount point
    // is already fixed in two other places — `cmd/oarlockd/app/app.go` mounts `/ui/`, and
    // `web/src/router/useRouter.ts` derives the same prefix — so this is the third, not
    // a new constraint.
    base: "/ui/",
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
