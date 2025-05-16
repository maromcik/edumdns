CREATE TYPE permission AS ENUM('create', 'read', 'update', 'delete');

CREATE TABLE IF NOT EXISTS "location"
(
    id            bigserial     PRIMARY KEY,
    ---------------------------------------------
    name          text          NOT NULL
);


CREATE TABLE IF NOT EXISTS "group"
(
    id            bigserial     PRIMARY KEY,
    ---------------------------------------------
    name          text          NOT NULL
);

CREATE TABLE IF NOT EXISTS "user"
(
    id              bigserial   PRIMARY KEY,
    ---------------------------------------------
    email           text UNIQUE NOT NULL,
    name            text        NOT NULL,
    surname         text        NOT NULL,
    password_hash   text        NOT NULL,
    password_salt   text        NOT NULL,
    admin           bool        NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    edited_at       timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz
);

CREATE TABLE IF NOT EXISTS "probe"
(
    id             uuid         PRIMARY KEY,
    ---------------------------------------------
    owner_id       bigint,
    location_id    bigint,
    adopted        bool         NOT NULL,
    mac            macaddr      NOT NULL,
    ip             cidr         NOT NULL,
    port           int          NOT NULL,
    vlan           int          NOT NULL,

    FOREIGN KEY (owner_id) REFERENCES "user" (id) ON DELETE SET NULL,
    FOREIGN KEY (location_id) REFERENCES "location" (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS "group_user"
(
    group_id        bigint      NOT NULL,
    user_id         bigint      NOT NULL,

    PRIMARY KEY (user_id, group_id),
    FOREIGN KEY (group_id) REFERENCES "group" (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES "user" (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "user_probe_permission"
(
    user_id         bigint      NOT NULL,
    probe_id        uuid        NOT NULL,
    permission      permission  NOT NULL,

    PRIMARY KEY (user_id, probe_id),
    FOREIGN KEY (user_id) REFERENCES "user" (id) ON DELETE CASCADE,
    FOREIGN KEY (probe_id) REFERENCES "probe" (id) ON DELETE CASCADE

);

CREATE TABLE IF NOT EXISTS "group_probe_permission"
(
    group_id        bigint      NOT NULL,
    probe_id        uuid        NOT NULL,
    permission      permission  NOT NULL,

    PRIMARY KEY (group_id, probe_id),
    FOREIGN KEY (group_id) REFERENCES "group" (id) ON DELETE CASCADE,
    FOREIGN KEY (probe_id) REFERENCES "probe" (id) ON DELETE CASCADE

);


CREATE TABLE IF NOT EXISTS "device"
(
    id             bigserial    PRIMARY KEY,
    probe_id       bigint       NOT NULL,
    mac            macaddr      NOT NULL,
    ip             cidr         NOT NULL,
    port           int          NOT NULL,
    duration       float8,
    interval       float8,

    UNIQUE (probe_id, mac)

);

CREATE TABLE IF NOT EXISTS "packet"
(
    id             bigserial    PRIMARY KEY,
    ---------------------------------------------
    device_id      bigint       NOT NULL,
    src_mac        macaddr      NOT NULL,
    dst_mac        macaddr      NOT NULL,
    src_addr       cidr         NOT NULL,
    dst_addr       cidr         NOT NULL,
    src_port       int          NOT NULL,
    dst_port       int          NOT NULL,
    payload        bytea        NOT NULL,

    FOREIGN KEY (device_id) REFERENCES "device" (id) ON DELETE CASCADE
);



CREATE INDEX IF NOT EXISTS "Probe_owner_id" ON "probe" (owner_id);
CREATE INDEX IF NOT EXISTS "Probe_location_id" ON "probe" (location_id);
CREATE INDEX IF NOT EXISTS "UserProbePermission_group_id_probe_id" ON "user_probe_permission" (user_id, probe_id);
CREATE INDEX IF NOT EXISTS "GroupProbePermission_group_id_probe_id" ON "group_probe_permission" (group_id, probe_id);
CREATE INDEX IF NOT EXISTS "Device_probe_id_mac" ON "device" (probe_id, mac);
CREATE INDEX IF NOT EXISTS "Packet_device_id" ON "packet" (device_id);