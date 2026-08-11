// @ts-nocheck
import { get } from '$lib/api';
import type { UserDetailTemplate } from '$lib/types';
import type { PageLoad } from './$types';

export const load = async ({ params }: Parameters<PageLoad>[0]) => {
	const template = await get<UserDetailTemplate>(`/user/${params.id}`);
	return { template };
};
