CREATE TABLE IF NOT EXISTS "location"
(
    id            bigserial     PRIMARY KEY,
    ---------------------------------------------
    name          text          NOT NULL,
    building      text,
    floor         int,
    room          int,
    address       text,
    city          text,
    description   text
);


CREATE TABLE IF NOT EXISTS "group"
(
    id            bigserial     PRIMARY KEY,
    ---------------------------------------------
    name          text          NOT NULL,
    description   text
);


CREATE TABLE IF NOT EXISTS "user"
(
    id              bigserial   PRIMARY KEY,
    ---------------------------------------------
    email           text UNIQUE NOT NULL,
    name            text        NOT NULL,
    surname         text        NOT NULL,
    password_hash   text,
    password_salt   text,
    admin           bool        NOT NULL DEFAULT false,
    disabled        bool        NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    edited_at       timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz
);

CREATE TABLE IF NOT EXISTS "probe"
(
    id                  uuid         PRIMARY KEY,
    ------------------------------  ---------------
    owner_id            bigint,
    location_id         bigint,
    adopted             bool         NOT NULL DEFAULT FALSE,
    mac                 macaddr      NOT NULL,
    ip                  cidr         NOT NULL,
    name                text,
    pre_shared_key      text,
    first_connected_at  timestamptz  DEFAULT now(),
    last_connected_at   timestamptz  DEFAULT now(),

    FOREIGN KEY (owner_id) REFERENCES "user" (id) ON DELETE SET NULL,
    FOREIGN KEY (location_id) REFERENCES "location" (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS "probe_config"
(
    id             bigserial    PRIMARY KEY,
    probe_id       uuid         NOT NULL,
    interface      text         NOT NULL,
    filter         text,

    UNIQUE (probe_id, interface, filter),
    FOREIGN KEY (probe_id) REFERENCES "probe" (id) ON DELETE CASCADE
);


CREATE TABLE IF NOT EXISTS "group_user"
(
    group_id        bigint      NOT NULL,
    user_id         bigint      NOT NULL,

    PRIMARY KEY (user_id, group_id),
    FOREIGN KEY (group_id) REFERENCES "group" (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES "user" (id) ON DELETE CASCADE
);


CREATE TABLE IF NOT EXISTS "group_probe_permission"
(
    group_id        bigint      NOT NULL,
    probe_id        uuid        NOT NULL,
    permission      smallint    NOT NULL,

    PRIMARY KEY (group_id, probe_id, permission),
    FOREIGN KEY (group_id) REFERENCES "group" (id) ON DELETE CASCADE,
    FOREIGN KEY (probe_id) REFERENCES "probe" (id) ON DELETE CASCADE
);


CREATE TABLE IF NOT EXISTS "device"
(
    id                     bigserial    PRIMARY KEY,
    probe_id               uuid         NOT NULL,
    mac                    macaddr      NOT NULL,
    ip                     cidr         NOT NULL,
    port                   int          NOT NULL,
    name                   text,
    duration               bigint       NOT NULL DEFAULT 120,
    interval               bigint       NOT NULL DEFAULT 100,
    published              bool         NOT NULL DEFAULT FALSE,
    proxy                  bool         NOT NULL DEFAULT TRUE,
    exclusive              bool         NOT NULL DEFAULT FALSE,
    acl_src_cidr           cidr,
    acl_pwd_hash           text,
    acl_pwd_salt           text,
    acl_ap_hostname_regex  text,
    discovered_at          timestamptz  DEFAULT now(),

    UNIQUE (probe_id, mac, ip),
    FOREIGN KEY (probe_id) REFERENCES "probe" (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "packet"
(
    id             bigserial    PRIMARY KEY,
    ---------------------------------------------
    probe_id       uuid         NOT NULL,
    src_mac        macaddr      NOT NULL,
    dst_mac        macaddr      NOT NULL,
    src_addr       cidr         NOT NULL,
    dst_addr       cidr         NOT NULL,
    src_port       int          NOT NULL,
    dst_port       int          NOT NULL,
    payload        bytea        NOT NULL,
    payload_hash   bigint       NOT NULL,
    payload_string text,
    captured_at    timestamptz  DEFAULT now(),

    UNIQUE (probe_id, src_mac, src_addr, dst_addr, dst_port, payload_hash),
    FOREIGN KEY (probe_id) REFERENCES "probe" (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "packet_transmit_request"
(
    id             bigserial    PRIMARY KEY,
    device_id      bigserial    NOT NULL,
    user_id        bigserial    NOT NULL,
    target_ip      cidr         NOT NULL,
    target_port    int          NOT NULL,
    permanent      bool         NOT NULL DEFAULT FALSE,
    created_at     timestamptz,
    UNIQUE (device_id, target_ip, target_port),
    FOREIGN KEY (device_id) REFERENCES "device" (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES "user" (id) ON DELETE CASCADE
);


CREATE INDEX IF NOT EXISTS "Probe_owner_id" ON "probe" (owner_id);
CREATE INDEX IF NOT EXISTS "Probe_location_id" ON "probe" (location_id);
CREATE INDEX IF NOT EXISTS "ProbeConfig_probe_id_if_filter" ON "probe_config" (probe_id, interface, filter);
CREATE INDEX IF NOT EXISTS "Device_probe_id_mac_ip" ON "device" (probe_id, mac, ip);
CREATE INDEX IF NOT EXISTS "Packet_probe_id_mac_ip" ON "packet" (probe_id, src_mac, src_addr);