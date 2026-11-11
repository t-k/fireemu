#!/usr/bin/env node
// The TASK-QUEUE-FUNCTIONS recording's entry point. See main.mjs.
import { main } from "./main.mjs";

process.exitCode = await main(process.argv.slice(2));
