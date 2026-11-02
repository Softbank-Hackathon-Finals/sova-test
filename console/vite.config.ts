import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: "/console/",
  plugins: [react()],
  build: { sourcemap: false },
  test: { environment: "node", restoreMocks: true },
});
