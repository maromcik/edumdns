// in dev, this makes Vite inject its client as this module's first dependency,
// so that global constant replacements are installed before any other module
// (including user hooks) evaluates. In build it's inert.
import.meta.hot;




export { matchers } from './matchers.js';

export const nodes = [
	() => import('./nodes/0'),
	() => import('./nodes/1'),
	() => import('./nodes/2'),
	() => import('./nodes/3'),
	() => import('./nodes/4'),
	() => import('./nodes/5'),
	() => import('./nodes/6'),
	() => import('./nodes/7'),
	() => import('./nodes/8'),
	() => import('./nodes/9'),
	() => import('./nodes/10'),
	() => import('./nodes/11'),
	() => import('./nodes/12'),
	() => import('./nodes/13'),
	() => import('./nodes/14'),
	() => import('./nodes/15'),
	() => import('./nodes/16'),
	() => import('./nodes/17'),
	() => import('./nodes/18'),
	() => import('./nodes/19')
];

export const server_loads = [];

export const dictionary = {
		"/(app)": [3,[2]],
		"/(app)/device": [4,[2]],
		"/(app)/device/create/[probe_id]": [7,[2]],
		"/(app)/device/[id]": [5,[2]],
		"/(app)/device/[id]/transmit": [6,[2]],
		"/(app)/group": [8,[2]],
		"/(app)/group/[id]": [9,[2]],
		"/login": [19],
		"/(app)/packet": [10,[2]],
		"/(app)/packet/create": [13,[2]],
		"/(app)/packet/[id]": [11,[2]],
		"/(app)/packet/[id]/update-payload": [12,[2]],
		"/(app)/probe": [14,[2]],
		"/(app)/probe/[id]": [15,[2]],
		"/(app)/user": [16,[2]],
		"/(app)/user/manage": [18,[2]],
		"/(app)/user/[id]": [17,[2]]
	};

export const hooks = {
	handleError: (({ error }) => { console.error(error) }),
	
	reroute: (() => {}),
	transport: {}
};

export const decoders = Object.fromEntries(Object.entries(hooks.transport).map(([k, v]) => [k, v.decode]));
export const encoders = Object.fromEntries(Object.entries(hooks.transport).map(([k, v]) => [k, v.encode]));

export const hash = false;

export const decode = (type, value) => decoders[type](value);

export { default as root } from '../root.js';

export const get_error_template = () => import('../shared/error-template.js').then(m => m.default);