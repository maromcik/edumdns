#!/usr/bin/env bash
# Installs everything needed to build the edumdns web frontend:
# Svelte 5 + SvelteKit 2, Vite, TypeScript, Tailwind CSS 3 and PostCSS.
#
# Requires Node.js 20+ and npm on PATH.
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v node >/dev/null 2>&1; then
    echo "ERROR: node is not installed. Install Node.js 20+ (e.g. via your package manager or nvm)." >&2
    exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
    echo "ERROR: npm is not installed. Install npm (usually distributed with Node.js)." >&2
    exit 1
fi

# Drop leftovers of the previous Tailwind-only setup so the install is reproducible.
rm -rf node_modules package-lock.json

# Installs (dev)dependencies declared in package.json, including:
#   svelte, @sveltejs/kit, @sveltejs/adapter-static, @sveltejs/vite-plugin-svelte,
#   vite, typescript, svelte-check, tailwindcss, postcss, autoprefixer
npm install

echo "Frontend dependencies installed. Build with ./build.sh"
