<script lang="ts">
	import { page } from '$app/state';

	const status = $derived(page.status);
	const description = $derived(page.error?.message ?? 'Something went wrong.');

	const title = $derived.by(() => {
		if (status >= 500) return 'Internal Server Error';
		switch (status) {
			case 404:
				return 'Page Not Found';
			case 403:
				return 'Access Denied';
			case 401:
				return 'Unauthorized';
			case 400:
				return 'Bad Request';
			default:
				return 'Something Went Wrong';
		}
	});

	const icon = $derived.by(() => {
		if (status >= 500) return 'fa-server';
		switch (status) {
			case 404:
				return 'fa-magnifying-glass-location';
			case 403:
				return 'fa-ban';
			case 401:
				return 'fa-lock';
			case 400:
				return 'fa-triangle-exclamation';
			default:
				return 'fa-circle-exclamation';
		}
	});

	const color = $derived.by(() => {
		if (status >= 500) return 'text-red-600 dark:text-red-400';
		switch (status) {
			case 404:
				return 'text-yellow-600 dark:text-yellow-400';
			case 403:
				return 'text-orange-600 dark:text-orange-400';
			case 401:
				return 'text-amber-600 dark:text-amber-400';
			case 400:
				return 'text-amber-600 dark:text-amber-400';
			default:
				return 'text-error';
		}
	});

	function refresh(): void {
		window.location.reload();
	}

	function back(): void {
		window.history.back();
	}
</script>

<div class="h-screen flex justify-center items-center p-4 bg-page">
	<div id="generic-error" class="w-full h-full flex justify-center items-center">
		<div
			class="bg-cards shadow-2xl rounded-2xl p-4 flex flex-col items-center text-center space-y-6 max-w-lg w-full"
		>
			<div class="{color} text-6xl mb-2">
				<i class="fa-solid {icon} drop-shadow-lg"></i>
			</div>
			<h2 class="{color} text-3xl font-semibold tracking-tight">{title}</h2>

			<div id="generic-error-area" class="text-sat-l space-y-1">
				<p class="text-lg font-mono text-sat-m text-center">{status}</p>
				<p class="text-base">{description}</p>
			</div>

			<div class="w-16 border-t border-base my-2"></div>

			<p class="text-sat-l text-sm">
				Please try refreshing the page, go back or return to the
				<a href="/" class="text-acc font-semibold hover:underline">homepage</a>.
			</p>

			<div class="flex gap-3 mt-2">
				<button
					onclick={back}
					class="inline-flex items-center gap-2 px-5 py-2 rounded-md bg-gray-400 dark:bg-gray-600 text-white hover:bg-gray-500 dark:hover:bg-gray-500 transition-all duration-150 shadow-sm"
				>
					<i class="fa-solid fa-arrow-left"></i>
					Go Back
				</button>

				<button
					onclick={refresh}
					class="inline-flex items-center gap-2 px-5 py-2 rounded-md bg-acc text-button hover:bg-acc-l transition-all duration-150 shadow-sm"
				>
					<i class="fa-solid fa-rotate-right"></i>
					Refresh
				</button>
			</div>
		</div>
	</div>
</div>
