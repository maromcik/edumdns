<script lang="ts">
	import Navbar from '$lib/components/Navbar.svelte';
	import Footer from '$lib/components/Footer.svelte';
	import type { LayoutProps } from './$types';

	let { children, data }: LayoutProps = $props();
</script>

<div class="flex pt-16 flex-col min-h-screen bg-page">
	<div
		class="2xl:w-5/6 2xl:max-w-5/6 w-full min-w-3/4 max-w-full mx-auto px-4 sm:px-8 py-6 sm:py-10 flex-1"
	>
		<!-- Main Content -->
		<main id="content-area">
			{@render children()}
		</main>
	</div>
</div>

<Footer />
<Navbar user={data.user} />
