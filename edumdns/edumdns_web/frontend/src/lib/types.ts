/**
 * TypeScript mirrors of the JSON structures exchanged with the Rust backend
 * (`edumdns_web`). Field names and optionality follow the serde
 * (de)serialization of the corresponding Rust structs.
 */

/** Database identifier (`edumdns_core::app_packet::Id`, i64). */
export type Id = number;
/** UUID serialized as string. */
export type Uuid = string;
/** MAC address serialized as string, e.g. "00:11:22:33:44:55". */
export type MacAddr = string;
/** IP network serialized as string, e.g. "192.168.1.10/32". */
export type IpNetwork = string;

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

export interface PageInfo {
	page: number;
	total_pages: number;
}

export interface GenericError {
	code: number;
	status_code: string;
	description: string;
}

export const ALL_PERMISSIONS = [
	'Full',
	'Read',
	'Adopt',
	'Forget',
	'Reconnect',
	'ModifyConfig',
	'Delete',
	'Update',
	'Create'
] as const;

export type Permission = (typeof ALL_PERMISSIONS)[number];

/** `edumdns_db::models::GroupProbePermission` */
export interface GroupProbePermission {
	group_id: Id;
	probe_id: Uuid;
	permission: Permission;
}

/** `edumdns_db::repositories::common::Permissions` (a type alias for a vec). */
export type Permissions = GroupProbePermission[];

/** Returns true when the permission set grants `permission` directly or via `Full`. */
export function hasPermission(permissions: Permissions, permission: Permission): boolean {
	return permissions.some((p) => p.permission === 'Full' || p.permission === permission);
}

// ---------------------------------------------------------------------------
// Entities (`edumdns_db`)
// ---------------------------------------------------------------------------

export interface Group {
	id: Id;
	name: string;
	description: string | null;
}

export interface User {
	id: Id;
	email: string;
	name: string;
	surname: string;
	password_hash: string | null;
	password_salt: string | null;
	admin: boolean;
	disabled: boolean;
	/** RFC 3339 timestamps produced by `time::OffsetDateTime`. */
	created_at: string;
	edited_at: string;
	deleted_at: string | null;
}

export interface ProbeConfig {
	id: Id;
	probe_id: Uuid;
	interface: string;
	filter: string | null;
}

export interface DeviceDisplay {
	id: Id;
	probe_id: Uuid;
	mac: MacAddr;
	ip: IpNetwork;
	port: number;
	name: string | null;
	duration: number;
	interval: number;
	published: boolean;
	proxy: boolean;
	exclusive: boolean;
	acl_src_cidr: IpNetwork | null;
	acl_pwd_hash: string | null;
	acl_ap_hostname_regex: string | null;
	discovered_at: string | null;
}

export interface PacketTransmitRequestDisplay {
	id: Id;
	user_id: Id;
	target_ip: IpNetwork;
	target_port: number;
	permanent: boolean;
	until: string | null;
}

export interface PacketDisplay {
	id: Id;
	probe_id: Uuid;
	src_mac: MacAddr;
	dst_mac: MacAddr;
	src_addr: IpNetwork;
	dst_addr: IpNetwork;
	src_port: number;
	dst_port: number;
	payload: string;
	payload_string: string | null;
	captured_at: string | null;
}

export interface ProbeDisplay {
	id: Uuid;
	owner_id: Id | null;
	location_id: Id | null;
	adopted: boolean;
	mac: MacAddr;
	ip: IpNetwork;
	name: string | null;
	pre_shared_key: string | null;
	first_connected_at: string | null;
	last_connected_at: string | null;
}

export interface UserDisplay {
	user: User;
	has_groups: boolean;
}

// ---------------------------------------------------------------------------
// Query filters (form queries, `edumdns_web::forms`)
// ---------------------------------------------------------------------------

export interface UserQuery {
	page?: number | null;
	email?: string | null;
	id?: Id | null;
	name?: string | null;
	surname?: string | null;
	admin?: boolean | null;
	disabled?: boolean | null;
}

export interface DeviceQuery {
	page?: number | null;
	id?: number | null;
	probe_id?: Uuid | null;
	mac?: MacAddr | null;
	ip?: IpNetwork | null;
	port?: number | null;
	name?: string | null;
	published?: boolean | null;
	proxy?: boolean | null;
	exclusive?: boolean | null;
}

export interface PacketQuery {
	page?: number | null;
	id?: Id | null;
	probe_id?: Uuid | null;
	src_mac?: MacAddr | null;
	dst_mac?: MacAddr | null;
	src_addr?: IpNetwork | null;
	dst_addr?: IpNetwork | null;
	src_port?: number | null;
	dst_port?: number | null;
	payload_string?: string | null;
}

export interface ProbeQuery {
	page?: number | null;
	id?: Uuid | null;
	owner_id?: Id | null;
	location_id?: Id | null;
	adopted?: boolean | null;
	mac?: MacAddr | null;
	ip?: IpNetwork | null;
	name?: string | null;
}

export interface GroupQuery {
	page?: number | null;
	name?: string | null;
	description?: string | null;
}

// ---------------------------------------------------------------------------
// API response payloads (former minijinja template contexts)
// ---------------------------------------------------------------------------

export interface IndexTemplate {
	user: UserDisplay;
}

export interface DeviceTemplate {
	user: UserDisplay;
	devices: DeviceDisplay[];
	page_info: PageInfo;
	filters: DeviceQuery;
	query_string: string;
}

export interface DeviceDetailTemplate {
	user: UserDisplay;
	permissions: Permissions;
	device: DeviceDisplay;
	packets: PacketDisplay[];
	packet_transmit_requests: PacketTransmitRequestDisplay[];
	page_info: PageInfo;
	filters: PacketQuery;
	query_string: string;
}

export interface DeviceTransmitTemplate {
	user: UserDisplay;
	device: DeviceDisplay;
	client_ip: string;
	packet_transmit_request: PacketTransmitRequestDisplay | null;
	in_progress: PacketTransmitRequestDisplay | null;
}

export interface DeviceCreateTemplate {
	probe_id: Uuid;
	user: UserDisplay;
}

export interface PacketTemplate {
	user: UserDisplay;
	packets: PacketDisplay[];
	page_info: PageInfo;
	filters: PacketQuery;
	query_string: string;
}

export interface PacketDetailTemplate {
	user: UserDisplay;
	permissions: Permissions;
	packet: PacketDisplay;
	device_id: Id | null;
}

export interface PacketCreateTemplate {
	user: UserDisplay;
	probe_id: Uuid;
	mac: MacAddr;
	ip: IpNetwork;
	port: number;
}

export interface PacketUpdatePayloadTemplate {
	user: UserDisplay;
	id: Id;
	probe_id: Uuid;
	mac: MacAddr;
	ip: IpNetwork;
	port: number;
	message: string;
}

/** One row of the probe permission matrix: per-permission flag list plus the group. */
export type PermissionMatrixRow = [Array<[Permission, boolean]>, Group];

export interface ProbeTemplate {
	user: UserDisplay;
	probes: ProbeDisplay[];
	page_info: PageInfo;
	filters: ProbeQuery;
	query_string: string;
}

export interface ProbeDetailTemplate {
	user: UserDisplay;
	permissions: Permissions;
	permission_matrix: PermissionMatrixRow[];
	probe: ProbeDisplay;
	devices: DeviceDisplay[];
	configs: ProbeConfig[];
	page_info: PageInfo;
	filters: DeviceQuery;
	query_string: string;
}

export interface UserTemplate {
	users: User[];
	user: UserDisplay;
	filters: UserQuery;
	page_info: PageInfo;
	query_string: string;
}

export interface UserDetailTemplate {
	user: UserDisplay;
	groups: Group[];
	target_user: UserDisplay;
}

export interface UserDetailGroupsTemplate {
	groups: Group[];
}

export interface UserManageProfileTemplate {
	user: UserDisplay;
	message: string;
	success: boolean;
	oidc: boolean;
}

export interface UserManagePasswordTemplate {
	message: string;
	success: boolean;
}

export interface GroupTemplate {
	user: UserDisplay;
	groups: Group[];
	filters: GroupQuery;
}

export interface GroupDetailTemplate {
	user: UserDisplay;
	users: User[];
	group: Group;
}

export interface GroupDetailUsersTemplate {
	users: User[];
}

export interface LoginResponse {
	return_url: string;
}

export interface CreateResponse {
	id: Id | Uuid;
}

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

export interface UserLoginForm {
	email: string;
	password: string;
	return_url: string;
}

export interface UserCreateForm {
	email: string;
	name: string;
	surname: string;
	admin: boolean;
	password: string;
	confirm_password: string;
}

export interface UserUpdateForm {
	email: string;
	name: string;
	surname: string;
}

export interface UserUpdateFormAdmin {
	id: Id;
	email?: string;
	name?: string;
	surname?: string;
	admin: boolean;
	disabled: boolean;
}

export interface UserUpdatePasswordForm {
	old_password: string;
	new_password: string;
	confirm_password: string;
}

export interface UserUpdatePasswordFormAdmin {
	id: Id;
	new_password: string;
	confirm_password: string;
}

export interface BulkAddEntityForm {
	entity_ids: Id[];
}

export interface CreateGroupForm {
	name: string;
	description?: string;
}

export interface UpdateGroupForm {
	id: Id;
	name: string;
	description?: string;
}

export interface CreateProbeForm {
	name: string;
}

export interface UpdateProbeForm {
	id: Uuid;
	name?: string;
	pre_shared_key?: string;
}

export interface UpdateProbeOwnerForm {
	id: Uuid;
	owner_id?: Id;
}

export interface ProbePermissionForm {
	group_id: Id;
	permission: Permission;
	value: boolean;
}

export interface ProbeConfigForm {
	interface: string;
	filter?: string;
}

export interface CreateDeviceForm {
	name: string;
	probe_id: Uuid;
	mac: MacAddr;
	ip: IpNetwork;
	port: number;
}

export interface UpdateDeviceForm {
	id: Id;
	name?: string;
	mac?: MacAddr;
	ip?: IpNetwork;
	port?: number;
	duration: number;
	interval: number;
	published: boolean;
	proxy: boolean;
	exclusive: boolean;
}

export interface DeviceCustomPacketTransmitRequest {
	target_ip: IpNetwork;
	target_port: number;
	permanent: boolean;
}

export interface DevicePacketTransmitRequest {
	acl_pwd?: string;
}

export interface UpdatePacketForm {
	id: Id;
	probe_id?: Uuid;
	src_mac?: MacAddr;
	dst_mac?: MacAddr;
	src_addr?: IpNetwork;
	dst_addr?: IpNetwork;
	src_port?: number;
	dst_port?: number;
}

export interface ReassignPacketForm {
	packet_id: Id;
	device_id: Id;
}

export interface PacketDeviceDataForm {
	probe_id: Uuid;
	mac: MacAddr;
	ip: IpNetwork;
	port: number;
}

// ---------------------------------------------------------------------------
// mDNS packet builder payloads (`hickory_proto::op::Message`),
// built client-side on the packet create / update-payload pages.
// ---------------------------------------------------------------------------

export interface DnsHeader {
	id: number;
	message_type: string;
	op_code: string;
	authoritative: boolean;
	truncation: boolean;
	recursion_desired: boolean;
	recursion_available: boolean;
	authentic_data: boolean;
	checking_disabled: boolean;
	response_code: string;
	query_count: number;
	answer_count: number;
	name_server_count: number;
	additional_count: number;
}

export interface DnsQuery {
	name: string;
	query_type: string;
	query_class: string;
	mdns_unicast_response: boolean;
}

export interface DnsRecord {
	name_labels: string;
	dns_class: string;
	ttl: number;
	rdata: Record<string, unknown>;
	mdns_cache_flush: boolean;
}

export interface DnsMessage {
	header: DnsHeader;
	queries: DnsQuery[];
	answers: DnsRecord[];
	name_servers: DnsRecord[];
	additionals: DnsRecord[];
	signature: string;
	edns: null;
}

export interface CreatePacketForm {
	probe_id: Uuid;
	src_mac: MacAddr;
	src_addr: IpNetwork;
	dst_port: number;
	message: DnsMessage;
}

export interface UpdatePacketPayloadForm {
	packet_id: Id;
	message: DnsMessage;
}
