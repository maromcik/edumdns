<script lang="ts">
	import { page } from '$app/state';
	import { onMount } from 'svelte';
	import { errorMessage, sendForm } from '$lib/api';
	import type { LoginResponse, UserLoginForm } from '$lib/types';

	let email = $state('');
	let password = $state('');
	let error = $state<string | null>(null);
	let submitting = $state(false);

	/** Where to send the user after a successful login (`ret` query parameter). */
	const returnUrl = $derived(page.url.searchParams.get('ret') ?? '/');

	onMount(() => {
		document.body.classList.add('h-screen', 'flex', 'justify-center', 'items-center', 'bg-page');
		return () => {
			document.body.classList.remove('h-screen', 'flex', 'justify-center', 'items-center', 'bg-page');
		};
	});

	async function submit(event: SubmitEvent): Promise<void> {
		event.preventDefault();
		submitting = true;
		error = null;
		const form: UserLoginForm = { email, password, return_url: returnUrl };
		try {
			const response = await sendForm<LoginResponse>('POST', '/login', form);
			// Full reload so the auth cookie/session is picked up afresh
			window.location.href = response.return_url || '/';
		} catch (err) {
			error = errorMessage(err);
			submitting = false;
		}
	}

	function oidcLogin(): void {
		window.location.href = `/oidc/redirect?ret=${encodeURIComponent(returnUrl)}`;
	}
</script>

<svelte:head>
	<title>edumdns - login</title>
</svelte:head>

<div id="login_box" class="w-full h-full flex justify-center items-center">
	<form
		onsubmit={submit}
		class="bg-cards shadow-lg rounded-lg p-5 flex flex-col items-center max-w-full w-96 mx-4 md:w-96 sm:w-96 lg:w-96 xl:w-1/4"
	>
		<h2 class="text-forms text-2xl mb-6">Login</h2>
		<div id="error-area" class="text-error mb-3">
			{error ?? ''}
		</div>
		<div class="w-full mb-6 flex flex-col gap-2.5">
			<input type="email" name="email" placeholder="Email" class="p-2.5 rounded" bind:value={email} required />
			<input
				type="password"
				name="password"
				placeholder="Heslo"
				class="p-2.5 rounded"
				bind:value={password}
				required
			/>
		</div>

		<!-- Local login button -->
		<button
			type="submit"
			disabled={submitting}
			class="w-full bg-acc rounded-md p-3 text-button text-lg shadow-md"
		>
			Login
		</button>

		<!-- Divider -->
		<div class="flex items-center my-4 w-full">
			<div class="flex-grow border-t border-gray-300"></div>
			<span class="mx-2 text-gray-500 text-sm">OR</span>
			<div class="flex-grow border-t border-gray-300"></div>
		</div>

		<!-- OIDC login button -->
		<button
			type="button"
			onclick={oidcLogin}
			class="w-full flex items-center justify-center gap-2 bg-blue-700 rounded-md p-3 text-lg shadow-md text-white"
		>
			<span>Login with </span>
			<img src="/static/images/muni-lg-white.png" alt="MUNI" class="h-10" />
		</button>
	</form>
</div>
