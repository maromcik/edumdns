/**
 * TypeScript port of the minijinja packet-builder JavaScript
 * (`templates/packet/create/content.html`, `templates/packet/edit/content.html`).
 *
 * The payload shape produced by {@link buildMessage} mirrors the template's
 * `buildCreatePacketJson()` exactly, including hickory_proto quirks such as
 * the string `response_code` and `"Unsigned"` signature. Because both the
 * create and update-payload handlers receive the raw JSON body that the old
 * JS octal-escaped (`utf8ToOctal`) before POSTing, {@link postOctalJson}
 * reproduces that encoding instead of sending plain `JSON.stringify` output.
 */

import { browser } from '$app/environment';
import { goto } from '$app/navigation';
import { ApiError } from '$lib/api';
import type { DnsMessage, DnsRecord, GenericError } from '$lib/types';

// ---------------------------------------------------------------------------
// Editable builder state
// ---------------------------------------------------------------------------

export type DnsMessageType = 'Query' | 'Response';
export type DnsOpCode = 'Query' | 'IQuery' | 'Status';
export type DnsResponseCode = 'NoError' | 'FormErr' | 'ServFail' | 'NXDomain';
export type DnsRecordType = 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT' | 'PTR' | 'SRV';
export type DnsQueryType = DnsRecordType | 'ANY';

export interface HeaderState {
	id: number | null;
	messageType: string;
	opCode: string;
	responseCode: string;
}

export interface QueryRow {
	/** Stable key for `{#each}` rendering. */
	key: number;
	name: string;
	queryType: string;
	queryClass: string;
}

export interface RecordRow {
	/** Stable key for `{#each}` rendering. */
	key: number;
	name: string;
	dnsClass: string;
	ttl: number | null;
	recordType: string;
	rdata: string;
	srvPriority: number | null;
	srvWeight: number | null;
	srvPort: number | null;
	srvTarget: string;
}

export interface BuilderState {
	header: HeaderState;
	queries: QueryRow[];
	answers: RecordRow[];
	additionals: RecordRow[];
}

let rowKey = 0;

export function newQueryRow(init?: Partial<Omit<QueryRow, 'key'>>): QueryRow {
	return {
		key: ++rowKey,
		name: init?.name ?? '',
		queryType: init?.queryType ?? 'A',
		queryClass: init?.queryClass ?? 'IN'
	};
}

export function newRecordRow(init?: Partial<Omit<RecordRow, 'key'>>): RecordRow {
	return {
		key: ++rowKey,
		name: init?.name ?? '',
		dnsClass: init?.dnsClass ?? 'IN',
		ttl: init?.ttl ?? 300,
		recordType: init?.recordType ?? 'A',
		rdata: init?.rdata ?? '',
		srvPriority: init?.srvPriority ?? null,
		srvWeight: init?.srvWeight ?? null,
		srvPort: init?.srvPort ?? null,
		srvTarget: init?.srvTarget ?? ''
	};
}

export function defaultBuilderState(): BuilderState {
	return {
		header: { id: 0, messageType: 'Query', opCode: 'Query', responseCode: 'NoError' },
		queries: [],
		answers: [],
		additionals: []
	};
}

// ---------------------------------------------------------------------------
// TXT parsing (verbatim port of `parseTxtValue`)
// ---------------------------------------------------------------------------

/** Splits a TXT value on `;`/`,` and UTF-8 encodes each part into byte arrays. */
export function parseTxtValue(raw: string): number[][] {
	const trimmed = (raw || '').trim();
	if (!trimmed) return [];
	const encoder = new TextEncoder();
	return trimmed
		.split(/\s*[;,]\s*/)
		.map((s) => s.trim())
		.filter(Boolean)
		.map((s) => Array.from(encoder.encode(s)));
}

// ---------------------------------------------------------------------------
// Payload building (verbatim port of `buildCreatePacketJson`)
// ---------------------------------------------------------------------------

function collectRecords(rows: RecordRow[]): DnsRecord[] {
	const out: DnsRecord[] = [];
	for (const row of rows) {
		const nameLabels = row.name.trim();
		if (!nameLabels) continue;
		const dnsClass = row.dnsClass.trim() || 'IN';
		const ttl = Number(row.ttl || 300);
		const type = row.recordType || 'A';
		let rdata: Record<string, unknown> | null = null;

		if (type === 'TXT') {
			const arr = parseTxtValue(row.rdata);
			if (arr.length) rdata = { TXT: { txt_data: arr } };
		} else if (type === 'SRV') {
			const priority = Number(row.srvPriority || 0);
			const weight = Number(row.srvWeight || 0);
			const port = Number(row.srvPort || 0);
			const target = row.srvTarget.trim();
			if (target) rdata = { SRV: { priority, weight, port, target } };
		} else {
			const raw = row.rdata.trim();
			if (raw) rdata = { [type]: raw };
		}

		if (rdata) {
			out.push({
				name_labels: nameLabels,
				dns_class: dnsClass,
				ttl,
				rdata,
				mdns_cache_flush: false
			});
		}
	}
	return out;
}

/** Builds the hickory_proto `Message` JSON exactly like the template JS. */
export function buildMessage(state: BuilderState): DnsMessage {
	const queries = state.queries
		.map((row) => ({
			name: row.name.trim(),
			queryType: row.queryType || 'A',
			queryClass: row.queryClass.trim() || 'IN'
		}))
		.filter((q) => q.name.length > 0)
		.map((q) => ({
			name: q.name,
			query_type: q.queryType,
			query_class: q.queryClass,
			mdns_unicast_response: false
		}));

	const answers = collectRecords(state.answers);
	const additionals = collectRecords(state.additionals);

	return {
		header: {
			id: Number(state.header.id || 0),
			message_type: state.header.messageType || 'Query',
			op_code: state.header.opCode || 'Query',
			authoritative: false,
			truncation: false,
			recursion_desired: false,
			recursion_available: false,
			authentic_data: false,
			checking_disabled: false,
			response_code: state.header.responseCode || 'NoError',
			query_count: queries.length,
			answer_count: answers.length,
			name_server_count: 0,
			additional_count: additionals.length
		},
		queries,
		answers,
		name_servers: [],
		additionals,
		signature: 'Unsigned',
		edns: null
	};
}

// ---------------------------------------------------------------------------
// Server message preloading (port of `preloadDnsMessage`)
// ---------------------------------------------------------------------------

interface ServerHeader {
	id?: number;
	message_type?: string;
	op_code?: string;
	response_code?: string;
}

interface ServerQuery {
	name?: string;
	query_type?: string;
	query_class?: unknown;
}

interface ServerRecord {
	name_labels?: string;
	dns_class?: unknown;
	ttl?: number;
	rdata?: Record<string, unknown>;
}

interface ServerMessage {
	header?: ServerHeader;
	queries?: ServerQuery[];
	answers?: ServerRecord[];
	additionals?: ServerRecord[];
}

/** The template pre-filled the class with `IN` whenever hickory serialized a non-plain variant. */
function serverClass(value: unknown): string {
	return typeof value === 'string' && value ? value : 'IN';
}

function txtToString(value: unknown): string {
	let parts: unknown[] = [];
	if (Array.isArray(value)) {
		parts = value;
	} else if (value && typeof value === 'object') {
		const txtData = (value as { txt_data?: unknown }).txt_data;
		if (Array.isArray(txtData)) parts = txtData;
	}
	const decoder = new TextDecoder();
	return parts
		.map((arr) => (Array.isArray(arr) ? decoder.decode(new Uint8Array(arr as number[])) : String(arr)))
		.join(', ');
}

function recordRowFromServer(rr: ServerRecord): RecordRow {
	const rdata = rr.rdata ?? {};
	const type = Object.keys(rdata)[0] ?? 'A';
	const value = rdata[type];
	const row = newRecordRow({
		name: rr.name_labels ?? '',
		dnsClass: serverClass(rr.dns_class),
		ttl: rr.ttl ?? 300,
		recordType: type
	});

	if (type === 'TXT') {
		row.rdata = txtToString(value);
	} else if (type === 'SRV') {
		const srv = (value ?? {}) as {
			priority?: number;
			weight?: number;
			port?: number;
			target?: string;
		};
		row.srvPriority = srv.priority ?? 0;
		row.srvWeight = srv.weight ?? 0;
		row.srvPort = srv.port ?? 0;
		row.srvTarget = srv.target ?? '';
	} else {
		row.rdata = value == null ? '' : String(value);
	}
	return row;
}

/**
 * Parses the `message` JSON string served by `update_packet_payload_form`
 * into builder rows, mirroring `preloadDnsMessage` (including `octalToUtf8`).
 * Returns `null` when the message is empty or not valid JSON.
 */
export function parseServerMessage(raw: string): BuilderState | null {
	const decoded = octalToUtf8(raw);
	if (!decoded || decoded.trim().length === 0) return null;

	let msg: ServerMessage;
	try {
		msg = JSON.parse(decoded) as ServerMessage;
	} catch {
		return null;
	}

	const state = defaultBuilderState();
	if (msg.header) {
		state.header.id = msg.header.id ?? 0;
		state.header.messageType = msg.header.message_type ?? 'Query';
		state.header.opCode = msg.header.op_code ?? 'Query';
		state.header.responseCode = msg.header.response_code ?? 'NoError';
	}
	if (Array.isArray(msg.queries)) {
		state.queries = msg.queries
			.filter((q) => q != null)
			.map((q) =>
				newQueryRow({
					name: q.name ?? '',
					queryType: q.query_type ?? 'A',
					queryClass: serverClass(q.query_class)
				})
			);
	}
	if (Array.isArray(msg.answers)) {
		state.answers = msg.answers.filter((rr) => rr != null).map(recordRowFromServer);
	}
	if (Array.isArray(msg.additionals)) {
		state.additionals = msg.additionals.filter((rr) => rr != null).map(recordRowFromServer);
	}
	return state;
}

// ---------------------------------------------------------------------------
// Octal encoding (verbatim port of `utf8ToOctal` / `octalToUtf8`)
// ---------------------------------------------------------------------------

/**
 * Escapes every byte outside the template's allowlist
 * (alphanumerics and `- . { [ ( } ] ) , " ' : _ /`) as an octal
 * sequence, which is the raw body shape the packet create / update-payload
 * handlers received from the legacy UI.
 */
export function utf8ToOctal(str: string): string {
	if (!str) return str;

	const bytes = new TextEncoder().encode(str);
	let out = '';
	for (const b of bytes) {
		const ch = String.fromCharCode(b);
		if (
			(b >= 0x30 && b <= 0x39) || // 0-9
			(b >= 0x41 && b <= 0x5a) || // A-Z
			(b >= 0x61 && b <= 0x7a) || // a-z
			ch === '-' ||
			ch === '.' ||
			ch === '{' ||
			ch === '[' ||
			ch === '(' ||
			ch === '}' ||
			ch === ']' ||
			ch === ')' ||
			ch === ',' ||
			ch === '"' ||
			ch === "'" ||
			ch === ':' ||
			ch === '_' ||
			ch === '/'
		) {
			out += ch;
		} else {
			out += '\\\\' + b.toString(8).padStart(3, '0');
		}
	}
	return out;
}

/** Inverse of {@link utf8ToOctal}, used to preload the server-provided message JSON. */
export function octalToUtf8(str: string): string {
	if (!str) return str;

	const bytes: number[] = [];
	let i = 0;
	while (i < str.length) {
		if (str[i] === '\\' && i + 3 < str.length && /^[0-7]{3}$/.test(str.slice(i + 1, i + 4))) {
			bytes.push(parseInt(str.slice(i + 1, i + 4), 8));
			i += 4;
		} else {
			const encoded = new TextEncoder().encode(str[i]);
			bytes.push(...encoded);
			i += 1;
		}
	}
	return new TextDecoder().decode(new Uint8Array(bytes));
}

// ---------------------------------------------------------------------------
// Raw octal-encoded JSON POST (same request style as `$lib/api.ts`)
// ---------------------------------------------------------------------------

/**
 * POSTs `payload` as `application/json`, but with the body run through
 * {@link utf8ToOctal} first — this is the exact body shape the Actix handlers
 * (`web::Json<CreatePacketForm>` and the raw-`String` `update_packet_payload`)
 * were fed by the legacy templates.
 */
export async function postOctalJson<T = undefined>(path: string, payload: unknown): Promise<T> {
	const res = await fetch(`/api${path}`, {
		method: 'POST',
		credentials: 'same-origin',
		headers: { 'Content-Type': 'application/json' },
		body: utf8ToOctal(JSON.stringify(payload))
	});

	if (res.status === 401) {
		if (browser && !window.location.pathname.startsWith('/login')) {
			const ret = encodeURIComponent(window.location.pathname + window.location.search);
			await goto(`/login?ret=${ret}`);
		}
	}

	if (!res.ok) {
		let generic: GenericError = {
			code: res.status,
			status_code: res.statusText,
			description: res.statusText
		};
		try {
			generic = { ...generic, ...((await res.json()) as Partial<GenericError>) };
		} catch {
			// Non-JSON error body; keep the HTTP status fallback.
		}
		throw new ApiError(generic);
	}

	if (res.status === 204) return undefined as T;
	const text = await res.text();
	return (text ? JSON.parse(text) : undefined) as T;
}
