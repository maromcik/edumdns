import { get } from '$lib/api';
import type { GroupTemplate } from '$lib/types';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ url }) => {
	const sp = url.searchParams;
	const template = await get<GroupTemplate>('/group', {
		page: sp.get('page'),
		name: sp.get('name'),
		description: sp.get('description')
	});
	return { template };
};
