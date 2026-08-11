// @ts-nocheck
import { get } from '$lib/api';
import type { IndexTemplate } from '$lib/types';
import type { LayoutLoad } from './$types';

/**
 * Every authenticated page needs the current user for the navbar. A 401 here
 * redirects to `/login` (handled by the API helper).
 */
export const load = async () => {
	const { user } = await get<IndexTemplate>('/');
	return { user };
};
;null as any as LayoutLoad;