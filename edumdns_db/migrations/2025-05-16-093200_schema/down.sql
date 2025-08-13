DROP TABLE IF EXISTS "location", "user", "group", "probe", "probe_config", "group_user", "group_probe_permission", "device", "packet" CASCADE;
DROP INDEX IF EXISTS "Probe_owner_id";
DROP INDEX IF EXISTS "Probe_location_id";
DROP INDEX IF EXISTS "ProbeConfig_probe_id";
DROP INDEX IF EXISTS "GroupProbePermission_group_id_probe_id";
DROP INDEX IF EXISTS "Device_probe_id_mac";
DROP INDEX IF EXISTS "Packet_device_id";
DROP TYPE IF EXISTS permission