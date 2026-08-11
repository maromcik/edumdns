/**
 * Thin typed wrapper around the JSON API mounted at `/api`.
 *
 * Conventions:
 * - All GET endpoints return JSON mirrors of the former template contexts.
 * - Mutations (POST/PUT/DELETE) return `204 NoContent`, or a JSON payload for
 *   creates (`{ id }`), logins (`{ return_url }`) and searches.
 * - Most POST/PUT endpoints consume `application/x-www-form-urlencoded`
 *   (Actix `web::Form`); use {@link sendForm}. A few endpoints consume JSON;
 *   use {@link sendJson} for those.
 * - Errors are returned as `GenericError` JSON and surfaced as {@link ApiError}.
 * - A `401` redirects the browser to the login page (client-side).
 */

import { browser } from '$app/environment';
import { goto } from '$app/navigation';
import type { GenericError } from './types';

const API_BASE = '/api';

export class ApiError extends Error {
	readonly generic: GenericError;

	constructor(generic: GenericError) {
		super(generic.description);
		this.name = 'ApiError';
		this.generic = generic;
	}
}

export type QueryValue = string | number | boolean | null | undefined;

/** Builds a query string, skipping `null`/`undefined` values. */
export function buildQuery(params?: Record<string, QueryValue>): string {
	if (!params) return '';
	const sp = new URLSearchParams();
	for (const [key, value] of Object.entries(params)) {
		if (value === null || value === undefined || value === '') continue;
		sp.set(key, String(value));
	}
	const s = sp.toString();
	return s ? `?${s}` : '';
}

/** Extracts a readable message from an unknown caught error. */
export function errorMessage(err: unknown): string {
	if (err instanceof ApiError) return err.generic.description;
	if (err instanceof Error) return err.message;
	return String(err);
}

async function parseError(res: Response): Promise<ApiError> {
	const fallback: GenericError = {
		code: res.status,
		status_code: res.statusText,
		description: res.statusText
	};
	try {
		const body = (await res.json()) as Partial<GenericError>;
		return new ApiError({ ...fallback, ...body });
	} catch {
		return new ApiError(fallback);
	}
}

async function request<T>(
	method: string,
	path: string,
	init: RequestInit = {},
	query?: Record<string, QueryValue>
): Promise<T> {
	const res = await fetch(`${API_BASE}${path}${buildQuery(query)}`, {
		method,
		credentials: 'same-origin',
		...init
	});

	if (res.status === 401) {
		if (browser && !window.location.pathname.startsWith('/login')) {
			const ret = encodeURIComponent(window.location.pathname + window.location.search);
			await goto(`/login?ret=${ret}`);
		}
		throw await parseError(res);
	}
	if (!res.ok) throw await parseError(res);
	if (res.status === 204) return undefined as T;
	const text = await res.text();
	if (!text) return undefined as T;
	try {
		return JSON.parse(text) as T;
	} catch {
		throw new ApiError({
			code: res.status,
			status_code: res.statusText,
			description: 'The server returned an unexpected non-JSON response.'
		});
	}
}

/** GET with an optional query object. */
export function get<T>(path: string, query?: Record<string, QueryValue>): Promise<T> {
	return request<T>('GET', path, {}, query);
}

/** POST/PUT/DELETE with form-url-encoded body (Actix `web::Form`). */
export function sendForm<T = undefined>(
	method: 'POST' | 'PUT' | 'DELETE',
	path: string,
	data?: object
): Promise<T> {
	const body = new URLSearchParams();
	if (data) {
		for (const [key, value] of Object.entries(data) as [string, QueryValue][]) {
			if (value === null || value === undefined) continue;
			body.append(key, String(value));
		}
	}
	return request<T>(method, path, {
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: body.toString()
	});
}

/** POST/PUT with a JSON body (Actix `web::Json` and raw JSON endpoints). */
export function sendJson<T = undefined>(
	method: 'POST' | 'PUT' | 'DELETE',
	path: string,
	data: unknown
): Promise<T> {
	return request<T>(method, path, {
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(data)
	});
}

/** GET (used by several state-changing legacy endpoints such as adopt/forget/publish). */
export function getAction<T = undefined>(path: string): Promise<T> {
	return request<T>('GET', path);
}
