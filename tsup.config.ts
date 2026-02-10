import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["cjs"],
  dts: true,
  splitting: false,
  clean: true,
  minify: true,
  noExternal: ["@noble/ciphers", "@scure/base"],
});
