
// this file is generated — do not edit it


declare module "svelte/elements" {
	export interface HTMLAttributes<T> {
		'data-sveltekit-keepfocus'?: true | '' | 'off' | undefined | null;
		'data-sveltekit-noscroll'?: true | '' | 'off' | undefined | null;
		'data-sveltekit-preload-code'?:
			| true
			| ''
			| 'eager'
			| 'viewport'
			| 'hover'
			| 'tap'
			| 'off'
			| undefined
			| null;
		'data-sveltekit-preload-data'?: true | '' | 'hover' | 'tap' | 'off' | undefined | null;
		'data-sveltekit-reload'?: true | '' | 'off' | undefined | null;
		'data-sveltekit-replacestate'?: true | '' | 'off' | undefined | null;
	}
}

export {};


declare module "$app/types" {
	type MatcherParam<M> = M extends (param : string) => param is (infer U extends string) ? U : string;

	export interface AppTypes {
		RouteId(): "/(app)" | "/" | "/(app)/device" | "/(app)/device/create" | "/(app)/device/create/[probe_id]" | "/(app)/device/[id]" | "/(app)/device/[id]/transmit" | "/(app)/group" | "/(app)/group/[id]" | "/login" | "/(app)/packet" | "/(app)/packet/create" | "/(app)/packet/[id]" | "/(app)/packet/[id]/update-payload" | "/(app)/probe" | "/(app)/probe/[id]" | "/(app)/user" | "/(app)/user/manage" | "/(app)/user/[id]";
		RouteParams(): {
			"/(app)/device/create/[probe_id]": { probe_id: string };
			"/(app)/device/[id]": { id: string };
			"/(app)/device/[id]/transmit": { id: string };
			"/(app)/group/[id]": { id: string };
			"/(app)/packet/[id]": { id: string };
			"/(app)/packet/[id]/update-payload": { id: string };
			"/(app)/probe/[id]": { id: string };
			"/(app)/user/[id]": { id: string }
		};
		LayoutParams(): {
			"/(app)": { probe_id?: string | undefined; id?: string | undefined };
			"/": { probe_id?: string | undefined; id?: string | undefined };
			"/(app)/device": { probe_id?: string | undefined; id?: string | undefined };
			"/(app)/device/create": { probe_id?: string | undefined };
			"/(app)/device/create/[probe_id]": { probe_id: string };
			"/(app)/device/[id]": { id: string };
			"/(app)/device/[id]/transmit": { id: string };
			"/(app)/group": { id?: string | undefined };
			"/(app)/group/[id]": { id: string };
			"/login": Record<string, never>;
			"/(app)/packet": { id?: string | undefined };
			"/(app)/packet/create": Record<string, never>;
			"/(app)/packet/[id]": { id: string };
			"/(app)/packet/[id]/update-payload": { id: string };
			"/(app)/probe": { id?: string | undefined };
			"/(app)/probe/[id]": { id: string };
			"/(app)/user": { id?: string | undefined };
			"/(app)/user/manage": Record<string, never>;
			"/(app)/user/[id]": { id: string }
		};
		Pathname(): "/" | "/device" | `/device/create/${string}` & {} | `/device/${string}` & {} | `/device/${string}/transmit` & {} | "/group" | `/group/${string}` & {} | "/login" | "/packet" | "/packet/create" | `/packet/${string}` & {} | `/packet/${string}/update-payload` & {} | "/probe" | `/probe/${string}` & {} | "/user" | "/user/manage" | `/user/${string}` & {};
		ResolvedPathname(): `${"" | `/${string}`}${ReturnType<AppTypes['Pathname']>}`;
		Asset(): string & {};
	}
}