import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [sveltekit()],
	server: {
		proxy: {
			// Proxy API calls and static assets to the Rust backend during development
			'/api': 'http://localhost:3000',
			'/static': 'http://localhost:3000',
			'/oidc': 'http://localhost:3000',
			'/logout': 'http://localhost:3000'
		}
	}
});
