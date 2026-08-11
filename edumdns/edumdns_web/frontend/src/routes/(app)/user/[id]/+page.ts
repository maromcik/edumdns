import { get } from '$lib/api';
import type { UserDetailTemplate } from '$lib/types';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ params }) => {
	const template = await get<UserDetailTemplate>(`/user/${params.id}`);
	return { template };
};
