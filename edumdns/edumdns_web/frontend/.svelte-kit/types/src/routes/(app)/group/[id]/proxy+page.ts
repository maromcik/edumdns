// @ts-nocheck
import { get } from '$lib/api';
import type { GroupDetailTemplate } from '$lib/types';
import type { PageLoad } from './$types';

export const load = async ({ params }: Parameters<PageLoad>[0]) => {
	const template = await get<GroupDetailTemplate>(`/group/${params.id}`);
	return { template };
};
