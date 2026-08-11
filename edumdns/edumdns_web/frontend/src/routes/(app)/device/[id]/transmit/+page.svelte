<script lang="ts">
	import { goto, invalidateAll } from '$app/navigation';
	import { errorMessage, sendForm } from '$lib/api';
	import ErrorAlert from '$lib/components/ErrorAlert.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const template = $derived(data.template);
	const device = $derived(template.device);
	const request = $derived(template.packet_transmit_request);

	// ---------------------------------------------------------------------------
	// Shared mutation plumbing
	// ---------------------------------------------------------------------------
	let actionError = $state<string | null>(null);

	async function runAction(fn: () => Promise<unknown>) {
		actionError = null;
		try {
			await fn();
			await invalidateAll();
		} catch (err) {
			actionError = errorMessage(err);
		}
	}

	// ---------------------------------------------------------------------------
	// Discovery request / extension (POST device/{id}/transmit[/request_id/extend])
	// ---------------------------------------------------------------------------
	let aclPwd = $state('');

	async function discover(event: Event) {
		event.preventDefault();
		await runAction(() =>
			sendForm('POST', `/device/${device.id}/transmit`, { acl_pwd: aclPwd })
		);
		aclPwd = '';
	}

	async function extend(event: Event) {
		event.preventDefault();
		if (!request) return;
		await runAction(() =>
			sendForm('POST', `/device/${device.id}/transmit/${request.id}/extend`, {
				acl_pwd: aclPwd
			})
		);
		aclPwd = '';
	}

	const stop = () =>
		runAction(() => {
			if (!request) return Promise.resolve();
			return sendForm('DELETE', `/device/${device.id}/transmit/${request.id}`);
		});

	// ---------------------------------------------------------------------------
	// Custom transmission (POST device/{id}/transmit-custom)
	// ---------------------------------------------------------------------------
	let targetIp = $state('');
	let targetPort = $state('');
	let permanent = $state(false);

	async function transmitCustom(event: Event) {
		event.preventDefault();
		await runAction(() =>
			sendForm('POST', `/device/${device.id}/transmit-custom`, {
				target_ip: targetIp,
				target_port: targetPort,
				permanent
			})
		);
	}
</script>

<svelte:head>
	<title>edumdns - Device {device.name ?? device.id} Transmit</title>
</svelte:head>

<div id="transmit-form" class="max-w-7xl mx-auto px-4 sm:px-8">
	<section class="text-center py-12 mb-3">
		<div class="flex items-center justify-center gap-2 mb-8">
			<button
				onclick={() => goto(`/device/${device.id}`)}
				class="flex items-center justify-center w-10 h-10 rounded-md border border-base bg-cards text-lg font-medium text-acc hover:text-acc-xl transition-colors"
			>
				←
			</button>
			<h2 class="text-3xl md:text-4xl font-extrabold text-sat-xl tracking-tight">
				Discover device {device.name === null ? device.id : device.name}
			</h2>
		</div>

		<!-- Device Info Card -->
		<div class="rounded-xl bg-cards p-8 shadow-lg mb-10 text-left">
			<h3 class="text-xl md:text-2xl font-semibold mb-6 text-sat-l flex items-center gap-2">
				<svg
					xmlns="http://www.w3.org/2000/svg"
					class="h-6 w-6 text-acc"
					fill="none"
					viewBox="0 0 24 24"
					stroke="currentColor"
				>
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-2a4 4 0 014-4h6" />
				</svg>
				Device Information
			</h3>
			<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
				<div class="flex flex-col">
					<span class="text-xs uppercase tracking-wide text-sat-m">ID</span>
					<span class="font-mono text-code truncate"><code>{device.id}</code></span>
				</div>
				<div class="flex flex-col">
					<span class="text-xs uppercase tracking-wide text-sat-m">Name</span>
					<span class="font-mono text-code truncate"><code>{device.name}</code></span>
				</div>
				<div class="flex flex-col">
					<span class="text-xs uppercase tracking-wide text-sat-m">Device MAC</span>
					<span class="font-mono text-code truncate"><code>{device.mac}</code></span>
				</div>
				<div class="flex flex-col">
					<span class="text-xs uppercase tracking-wide text-sat-m">Device IP</span>
					<span class="font-mono text-code truncate"><code>{device.ip}</code></span>
				</div>
				<div class="flex flex-col">
					<span class="text-xs uppercase tracking-wide text-sat-m">Transmit Duration</span>
					<span class="font-mono text-code truncate"><code>{device.duration} seconds</code></span>
				</div>
				<div class="flex flex-col">
					<span class="text-xs uppercase tracking-wide text-sat-m">Transmit Interval</span>
					<span class="font-mono text-code truncate"><code>{device.interval} ms</code></span>
				</div>
				<div class="flex flex-col">
					<span class="text-xs uppercase tracking-wide text-sat-m">Via Proxy</span>
					<span class="font-mono text-code truncate"><code>{device.proxy}</code></span>
				</div>
				<div class="flex flex-col">
					<span class="text-xs uppercase tracking-wide text-sat-m">Exclusive</span>
					<span class="font-mono text-code truncate"><code>{device.exclusive}</code></span>
				</div>
			</div>
		</div>

		<ErrorAlert message={actionError} />

		<!-- Client IP + Transmission Controls -->
		<div id="transmit-result" class="mt-10">
			<div class="rounded-2xl bg-cards p-10 shadow-xl">
				<div class="flex flex-col items-center justify-center gap-8">
					<!-- Your IP -->
					<div class="flex flex-col items-center gap-3">
						<span
							class="text-sm md:text-lg uppercase tracking-wide text-sat-l font-semibold flex items-center gap-2"
						>
							<i class="fa-solid fa-network-wired text-acc"></i>
							Your IP Address
						</span>
						<div class="px-4 py-2  border border-permanent rounded-lg">
							<span class="text-2xl font-mono text-sat-xl tracking-tight select-all"
								>{template.client_ip}</span
							>
						</div>
					</div>

					{#if template.in_progress !== null && request === null}
						<!-- Warning: Transmission in progress -->
						<div
							class="w-full max-w-lg bg-yellow-50 border-l-4 border-yellow-500 text-yellow-900 p-5 rounded-md text-left"
						>
							<div class="flex items-center gap-3">
								<i class="fa-solid fa-triangle-exclamation text-yellow-600 text-xl"></i>
								<h3 class="text-lg font-semibold">Discovery In Progress</h3>
							</div>
							<p class="mt-2 text-sm">
								Another discovery for this device is currently running. Please wait until it
								completes on <span class="font-mono">{template.in_progress.until}</span>.
							</p>
						</div>
					{:else}
						<!-- Transmission Controls -->
						<div class="flex flex-col items-center justify-center gap-6 w-full">
							{#if request !== null}
								<!-- Discovery Active -->
								{#if request.until !== null}
									<div class="w-full max-w-md">
										<div
											class="flex flex-col sm:flex-row items-center justify-between w-full px-8 py-4 rounded-xl border border-permanent "
										>
											<div>
												<p class="font-semibold text-sat-l">
													<i class="fa-solid fa-clock text-sat-l text-lg pr-2"></i>
													Discovery Active
												</p>
												<p class="text-sm text-sat-l">
													Until {request.until}
												</p>
											</div>

											<!-- Stop Button (small but strong) -->
											<button
												onclick={stop}
												type="submit"
												class="inline-flex items-center gap-2 rounded-lg border border-red-600 bg-red-500 text-button px-4 py-2 text-sm font-semibold hover:bg-red-600 transition"
											>
												<i class="fa-solid fa-stop"></i>
												Stop
											</button>
										</div>
									</div>
								{/if}

								<!-- Extend Discovery Form -->
								<form
									onsubmit={extend}
									class="flex flex-col items-center gap-5 w-full max-w-sm bg-base/10 p-6 rounded-xl border border-permanent"
								>
									{#if device.acl_pwd_hash !== null}
										<div class="w-full text-left">
											<label
												for="acl_pwd_extend"
												class="text-xs uppercase tracking-wide text-sat-l mb-1 block"
												>Password</label
											>
											<input
												id="acl_pwd_extend"
												name="acl_pwd"
												type="password"
												bind:value={aclPwd}
												class="w-full rounded-md border border-base bg-bg px-3 py-2 bg-panes text-sat-l placeholder-sat-m"
												placeholder="Enter password"
											/>
										</div>
									{/if}

									<button
										type="submit"
										class="inline-flex items-center justify-center gap-3 rounded-xl bg-acc text-button px-6 py-3 text-lg font-semibold hover:bg-acc-xl transition"
									>
										<i class="fa-solid fa-arrows-rotate"></i>
										Extend Discovery
									</button>
								</form>
							{:else}
								<!-- Initial Discover Form -->
								<form
									onsubmit={discover}
									class="flex flex-col items-center gap-5 w-full max-w-sm bg-base/10 p-6 rounded-xl border border-permanent"
								>
									{#if device.acl_pwd_hash !== null}
										<div class="w-full text-left">
											<label
												for="acl_pwd"
												class="text-xs uppercase tracking-wide text-sat-l mb-1 block"
												>Password</label
											>
											<input
												id="acl_pwd"
												name="acl_pwd"
												type="password"
												bind:value={aclPwd}
												class="w-full rounded-md border border-base bg-bg px-3 py-2 bg-panes text-sat-l focus:outline-none placeholder-sat-m"
												placeholder="Enter password"
											/>
										</div>
									{/if}

									<button
										type="submit"
										class="inline-flex items-center justify-center gap-3 rounded-xl bg-acc text-button px-6 py-3 text-lg font-semibold  hover:bg-primary/90 transition-colors"
									>
										<i class="fa-solid fa-search"></i>
										Discover
									</button>
								</form>
							{/if}
						</div>
					{/if}
				</div>
			</div>
		</div>

		<!-- Custom Transmission -->
		<div class="rounded-xl bg-cards p-8 shadow-lg mt-10 text-left">
			<h3 class="text-xl md:text-2xl font-semibold mb-6 text-sat-l">
				Request Custom Packet Transmission
			</h3>
			<form class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4" onsubmit={transmitCustom}>
				<!-- Target IP -->
				<div class="flex flex-col">
					<label for="target_ip" class="text-xs uppercase tracking-wide text-forms"
						>Target IP</label
					>
					<input
						id="target_ip"
						name="target_ip"
						type="text"
						inputmode="numeric"
						placeholder="e.g., 8.8.8.8"
						bind:value={targetIp}
						required
						class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
					/>
					<p class="text-xs text-sat-m mt-1">Destination IPv4/IPv6 subnet.</p>
				</div>

				<!-- Target Port -->
				<div class="flex flex-col">
					<label for="target_port" class="text-xs uppercase tracking-wide text-forms"
						>Target Port</label
					>
					<input
						id="target_port"
						name="target_port"
						type="number"
						min="1"
						max="65535"
						placeholder="e.g., 53"
						bind:value={targetPort}
						required
						class="mt-1 rounded-md border border-base bg-panes px-3 py-2 text-sat-l focus:outline-none focus:ring-2 focus:ring-acc"
					/>
					<p class="text-xs text-sat-m mt-1">Destination TCP/UDP port (1–65535).</p>
				</div>

				<div class="md:col-span-2 flex items-center gap-2">
					<input
						id="permanent"
						name="permanent"
						type="checkbox"
						class="h-4 w-4 rounded border-base bg-panes text-acc focus:ring-2 focus:ring-acc"
						bind:checked={permanent}
					/>
					<label for="permanent" class="text-sm text-sat-l">Permanent</label>
				</div>

				<!-- Actions -->
				<div class="md:col-span-2 flex items-center gap-2">
					<button
						type="submit"
						class="inline-flex items-center rounded-md bg-acc px-4 py-2 text-sm font-medium text-button transition-colors"
					>
						Transmit
					</button>
				</div>
			</form>
		</div>
	</section>
</div>
