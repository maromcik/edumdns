import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

// NOTE: Svelte does not support TypeScript for its own config file,
// so this file must remain JavaScript. All application code is TypeScript.
/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		adapter: adapter({
			// Output directly into edumdns_web/app, served by the Rust backend
			pages: '../app',
			assets: '../app',
			// SPA fallback the Rust side serves for unknown paths
			fallback: 'index.html',
			precompress: false,
			strict: false
		})
	}
};

export default config;
