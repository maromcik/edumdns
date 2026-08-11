import type { Config } from 'tailwindcss';

export default {
	content: ['./src/**/*.{html,svelte,ts}'],
	safelist: ['text-blue-500'],
	theme: {
		extend: {
			fontFamily: {
				handwriting: ['"Pacifico"', 'cursive']
			}
		}
	},
	plugins: []
} satisfies Config;
