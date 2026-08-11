import { get } from '$lib/api';
import type { UserManageProfileTemplate } from '$lib/types';
import type { PageLoad } from './$types';

export const load: PageLoad = async () => {
	const template = await get<UserManageProfileTemplate>('/user/manage');
	return { template };
};
