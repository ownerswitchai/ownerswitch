#!/usr/bin/env node
import { main } from "./main.js";

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
