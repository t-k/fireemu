#!/usr/bin/env bash
set -euo pipefail
exec node tools/sdk-smoke-database/rules-identity-replay.mjs "$FIREBASE_DATABASE_EMULATOR_HOST" "$1"
