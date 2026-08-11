import { get } from '$lib/api';
import type { GroupDetailTemplate } from '$lib/types';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ params }) => {
	const template = await get<GroupDetailTemplate>(`/group/${params.id}`);
	return { template };
};
