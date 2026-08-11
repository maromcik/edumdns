#!/usr/bin/env bash
# Builds the Svelte frontend.
#
# The static build output (index.html + bundled assets) is written to
# edumdns_web/app/ by @sveltejs/adapter-static (see svelte.config.js).
# The Rust backend serves that directory at "/".
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d node_modules ]; then
    echo "ERROR: node_modules is missing - run ./install.sh first." >&2
    exit 1
fi

# Type-check all Svelte/TypeScript sources first.
npm run check

# Produce the production build into ../app
npm run build

echo "Frontend built into $(cd ../app && pwd)"
