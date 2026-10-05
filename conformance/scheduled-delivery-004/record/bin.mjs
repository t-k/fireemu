#!/usr/bin/env node
// The delivery recorder's entry point. See main.mjs.
import { main } from "./main.mjs";

process.exitCode = await main(process.argv.slice(2));
