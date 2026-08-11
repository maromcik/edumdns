// @ts-nocheck
import { get } from '$lib/api';
import type { UserTemplate } from '$lib/types';
import type { PageLoad } from './$types';

export const load = async ({ url }: Parameters<PageLoad>[0]) => {
	const sp = url.searchParams;
	const template = await get<UserTemplate>('/user', {
		page: sp.get('page'),
		email: sp.get('email'),
		id: sp.get('id'),
		name: sp.get('name'),
		surname: sp.get('surname'),
		admin: sp.get('admin'),
		disabled: sp.get('disabled')
	});
	return { template };
};
