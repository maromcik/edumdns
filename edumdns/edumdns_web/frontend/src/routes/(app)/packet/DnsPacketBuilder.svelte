<script lang="ts">
	/**
	 * Reactive port of the mDNS packet builder UI from
	 * `templates/packet/create/content.html` and `templates/packet/edit/content.html`.
	 * The DOM-manipulating template JS (createEl / answerRowHtml / toggleSrvForRow)
	 * is replaced by arrays of row objects in `$state` rendered with `{#each}`.
	 */
	import { errorMessage } from '$lib/api';
	import ErrorAlert from '$lib/components/ErrorAlert.svelte';
	import type { DnsMessage } from '$lib/types';
	import {
		buildMessage,
		defaultBuilderState,
		newQueryRow,
		newRecordRow,
		type BuilderState,
		type QueryRow,
		type RecordRow
	} from './dns-builder';

	let {
		title,
		metadata,
		initial = null,
		onSubmit
	}: {
		title: string;
		metadata: { probeId: string; mac: string; ip: string; port: number };
		initial?: BuilderState | null;
		onSubmit: (message: DnsMessage) => Promise<void>;
	} = $props();

	let headerId = $state<number | null>(0);
	let messageType = $state('Query');
	let opCode = $state('Query');
	let responseCode = $state('NoError');

	let queries = $state<QueryRow[]>([]);
	let answers = $state<RecordRow[]>([]);
	let additionals = $state<RecordRow[]>([]);

	// Seed the form from the server-provided message (update-payload page).
	$effect.pre(() => {
		const state = initial ?? defaultBuilderState();
		headerId = state.header.id;
		messageType = state.header.messageType;
		opCode = state.header.opCode;
		responseCode = state.header.responseCode;
		queries = state.queries;
		answers = state.answers;
		additionals = state.additionals;
	});

	let previewOpen = $state(false);
	let submitting = $state(false);
	let submitError = $state<string | null>(null);

	function currentMessage(): DnsMessage {
		return buildMessage({
			header: { id: headerId, messageType, opCode, responseCode },
			queries,
			answers,
			additionals
		});
	}

	const previewJson = $derived(JSON.stringify(currentMessage(), null, 2));

	function addQuery() {
		queries = [...queries, newQueryRow()];
	}

	function addRecord(kind: 'answer' | 'additional') {
		if (kind === 'answer') answers = [...answers, newRecordRow()];
		else additionals = [...additionals, newRecordRow()];
	}

	function removeQuery(key: number) {
		queries = queries.filter((row) => row.key !== key);
	}

	function removeRecord(kind: 'answer' | 'additional', key: number) {
		if (kind === 'answer') answers = answers.filter((row) => row.key !== key);
		else additionals = additionals.filter((row) => row.key !== key);
	}

	async function handleSubmit(event: SubmitEvent) {
		event.preventDefault();
		submitting = true;
		submitError = null;
		try {
			await onSubmit(currentMessage());
		} catch (err) {
			submitError = errorMessage(err);
		} finally {
			submitting = false;
		}
	}
</script>

{#snippet recordRows(kind: 'answer' | 'additional', rows: RecordRow[])}
	{#each rows as row (row.key)}
		<div class="{kind}-row border-gray-500 dark:border-gray-300 border-2 rounded p-3">
			<!-- Responsive grid: 1 column on mobile, 6 columns on medium+ screens -->
			<div class="grid grid-cols-1 md:grid-cols-6 gap-2 items-start">
				<input
					type="text"
					placeholder="name_labels (example.com.)"
					class="{kind}-name md:col-span-2 rounded border px-2 py-1 w-full"
					bind:value={row.name}
				/>
				<input
					type="text"
					placeholder="class (IN)"
					class="{kind}-class w-full md:w-20 rounded border px-2 py-1"
					bind:value={row.dnsClass}
				/>
				<input
					type="number"
					placeholder="ttl"
					class="{kind}-ttl w-full md:w-24 rounded border px-2 py-1"
					bind:value={row.ttl}
				/>
				<select
					class="{kind}-type w-full md:w-24 rounded bg-gray-50 border px-2 py-1"
					bind:value={row.recordType}
				>
					<option value="A">A</option>
					<option value="AAAA">AAAA</option>
					<option value="CNAME">CNAME</option>
					<option value="MX">MX</option>
					<option value="TXT">TXT</option>
					<option value="PTR">PTR</option>
					<option value="SRV">SRV</option>
				</select>

				<!-- rdata -->
				<div
					class="{kind}-rdata-wrap col-span-1 md:col-span-6 mt-2"
					class:hidden={row.recordType === 'SRV'}
				>
					<input
						type="text"
						placeholder="rdata (e.g. 1.2.3.4, text, or PTR target)"
						class="{kind}-rdata w-full rounded border px-2 py-1"
						bind:value={row.rdata}
					/>
				</div>

				<!-- SRV subfields -->
				<div
					class="{kind}-srv-wrap col-span-1 md:col-span-6 mt-2"
					class:hidden={row.recordType !== 'SRV'}
				>
					<div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2 items-center">
						<input
							type="number"
							min="0"
							max="65535"
							placeholder="priority"
							class="{kind}-srv-priority rounded border px-2 py-1"
							bind:value={row.srvPriority}
						/>
						<input
							type="number"
							min="0"
							max="65535"
							placeholder="weight"
							class="{kind}-srv-weight rounded border px-2 py-1"
							bind:value={row.srvWeight}
						/>
						<input
							type="number"
							min="0"
							max="65535"
							placeholder="port"
							class="{kind}-srv-port rounded border px-2 py-1"
							bind:value={row.srvPort}
						/>
						<input
							type="text"
							placeholder="target (example.com.)"
							class="{kind}-srv-target rounded border px-2 py-1"
							bind:value={row.srvTarget}
						/>
					</div>
				</div>

				<!-- Delete button -->
				<div class="col-span-1 md:col-span-6 mt-2 flex justify-end">
					<button
						type="button"
						title="Remove record"
						onclick={() => removeRecord(kind, row.key)}
						class="inline-flex items-center rounded-md px-3 py-1 text-sm text-red-400 hover:text-red-500 hover:bg-muted/20 transition-colors"
					>
						<i class="fa-solid fa-trash"></i>
					</button>
				</div>
			</div>
		</div>
	{/each}
{/snippet}

<div class="max-w-7xl mx-auto px-4 sm:px-8">
	<form
		onsubmit={handleSubmit}
		class="space-y-6 bg-cards shadow-md rounded px-8 pt-6 pb-8"
	>
		<h2 class="text-xl text-sat-l font-bold text-center mb-4">{title}</h2>

		<!-- Metadata preview -->
		<div class="grid grid-cols-2 gap-4">
			<div>
				<label class="block text-xs text-forms uppercase mb-1" for="meta-probe-id">Probe ID</label>
				<div class="p-2 bg-forms-fields rounded border break-all" id="meta-probe-id">
					<code class="text-code">{metadata.probeId}</code>
				</div>
			</div>
			<div>
				<label class="block text-xs text-forms uppercase mb-1" for="meta-src-mac">Source MAC</label>
				<div class="p-2 rounded border bg-forms-fields break-all" id="meta-src-mac">
					<code class="text-code">{metadata.mac}</code>
				</div>
			</div>
			<div>
				<label class="block text-xs text-forms uppercase mb-1" for="meta-src-ip">Source IP</label>
				<div class="p-2 rounded border bg-forms-fields break-all" id="meta-src-ip">
					<code class="text-code">{metadata.ip}</code>
				</div>
			</div>
			<div>
				<label class="block text-xs text-forms uppercase mb-1" for="meta-dst-port">Dest Port</label>
				<div class="p-2 rounded border bg-forms-fields break-all" id="meta-dst-port">
					<code class="text-code">{metadata.port}</code>
				</div>
			</div>
		</div>

		<!-- Header -->
		<fieldset class="border-gray-500 dark:border-gray-300 border-4 dark:border-2 rounded p-4">
			<legend class="text-lg text-sat-xl font-semibold">DNS Header</legend>
			<div class="grid grid-cols-2 gap-4">
				<div>
					<label class="block text-xs text-forms uppercase mb-1" for="header-message-type">
						Message Type
					</label>
					<select
						id="header-message-type"
						class="w-full rounded border bg-gray-50 px-2 py-1"
						bind:value={messageType}
					>
						<option value="Query">Query</option>
						<option value="Response">Response</option>
					</select>
				</div>
				<div>
					<label class="block text-xs text-forms uppercase mb-1" for="header-op-code">Op Code</label>
					<select
						id="header-op-code"
						class="w-full bg-gray-50 rounded border px-2 py-1"
						bind:value={opCode}
					>
						<option value="Query">Query</option>
						<option value="IQuery">IQuery</option>
						<option value="Status">Status</option>
					</select>
				</div>
				<div>
					<label class="block text-xs text-forms uppercase mb-1" for="header-response-code">
						Response Code
					</label>
					<select
						id="header-response-code"
						class="w-full bg-gray-50 rounded border px-2 py-1"
						bind:value={responseCode}
					>
						<option value="NoError">NoError</option>
						<option value="FormErr">FormErr</option>
						<option value="ServFail">ServFail</option>
						<option value="NXDomain">NXDomain</option>
					</select>
				</div>
				<div>
					<label class="block text-xs text-forms uppercase mb-1" for="header-id">ID</label>
					<input
						id="header-id"
						type="number"
						min="0"
						max="65535"
						class="w-full text-forms-input bg-gray-50 rounded border px-2 py-1"
						bind:value={headerId}
					/>
				</div>
			</div>
		</fieldset>

		<!-- Queries -->
		<fieldset class="border-gray-500 dark:border-gray-300 border-4 dark:border-2 rounded p-4">
			<legend class="text-lg text-sat-xl font-semibold">Queries</legend>

			<div class="space-y-3">
				{#each queries as row (row.key)}
					<div
						class="query-row border-gray-500 dark:border-gray-300 border-2 dark:border rounded p-3 gap-2 items-center"
					>
						<input
							type="text"
							placeholder="name (example.com.)"
							class="query-name flex-1 rounded border px-2 py-1"
							bind:value={row.name}
						/>
						<select
							class="query-type w-28 rounded bg-gray-50 border px-2 py-1"
							bind:value={row.queryType}
						>
							<option value="A">A</option>
							<option value="AAAA">AAAA</option>
							<option value="ANY">ANY</option>
							<option value="CNAME">CNAME</option>
							<option value="MX">MX</option>
							<option value="TXT">TXT</option>
							<option value="PTR">PTR</option>
							<option value="SRV">SRV</option>
						</select>
						<input
							type="text"
							placeholder="class (IN)"
							class="text-forms-input query-class w-20 rounded border px-2 py-1 mt-2"
							bind:value={row.queryClass}
						/>
						<button
							type="button"
							title="Remove query"
							onclick={() => removeQuery(row.key)}
							class="inline-flex items-center rounded-md px-3 py-1 text-sm text-red-400 hover:text-red-500 hover:bg-muted/20 transition-colors"
						>
							<i class="fa-solid fa-trash"></i>
						</button>
					</div>
				{/each}
			</div>

			<div class="mt-2 flex gap-2">
				<button type="button" onclick={addQuery} class="bg-acc text-button px-3 py-1 rounded">
					+ Query
				</button>
			</div>
		</fieldset>

		<!-- Answers -->
		<fieldset class="border-gray-500 dark:border-gray-300 border-4 dark:border-2 rounded p-4">
			<legend class="text-lg text-forms font-semibold">Answers</legend>

			<div class="space-y-3">
				{@render recordRows('answer', answers)}
			</div>

			<div class="mt-2 flex gap-2">
				<button
					type="button"
					onclick={() => addRecord('answer')}
					class="bg-acc text-button px-3 py-1 rounded"
				>
					+ Answer
				</button>
			</div>
		</fieldset>

		<!-- Additionals -->
		<fieldset class="border-gray-500 dark:border-gray-300 border-4 dark:border-2 rounded p-4">
			<legend class="text-lg text-forms font-semibold">Additionals</legend>

			<div class="space-y-3">
				{@render recordRows('additional', additionals)}
			</div>

			<div class="mt-2 flex gap-2">
				<button
					type="button"
					onclick={() => addRecord('additional')}
					class="bg-acc text-button px-3 py-1 rounded"
				>
					+ Additional
				</button>
			</div>
		</fieldset>

		<div class="flex justify-end gap-3">
			<button
				type="button"
				onclick={() => (previewOpen = !previewOpen)}
				class="px-4 py-2 text-forms rounded border"
			>
				Preview JSON
			</button>
			<button
				type="submit"
				disabled={submitting}
				class="bg-acc hover:bg-acc-l text-button px-6 py-2 rounded"
			>
				Send Packet
			</button>
		</div>

		<ErrorAlert message={submitError} />
	</form>

	{#if previewOpen}
		<pre class="mt-4 p-3 bg-forms text-button rounded overflow-auto" style="max-height:40vh">{previewJson}</pre>
	{/if}
</div>
