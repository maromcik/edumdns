// @generated automatically by Diesel CLI.

diesel::table! {
    device (id) {
        id -> Int8,
        probe_id -> Uuid,
        mac -> Macaddr,
        ip -> Cidr,
        port -> Int4,
        name -> Nullable<Text>,
        duration -> Int8,
        interval -> Int8,
        published -> Bool,
        proxy -> Bool,
        acl_src_cidr -> Nullable<Cidr>,
        acl_pwd_hash -> Nullable<Text>,
        acl_pwd_salt -> Nullable<Text>,
        acl_ap_hostname_regex -> Nullable<Text>,
        discovered_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    group (id) {
        id -> Int8,
        name -> Text,
        description -> Nullable<Text>,
    }
}

diesel::table! {
    group_probe_permission (group_id, probe_id, permission) {
        group_id -> Int8,
        probe_id -> Uuid,
        permission -> Int2,
    }
}

diesel::table! {
    group_user (user_id, group_id) {
        group_id -> Int8,
        user_id -> Int8,
    }
}

diesel::table! {
    location (id) {
        id -> Int8,
        name -> Text,
        building -> Nullable<Text>,
        floor -> Nullable<Int4>,
        room -> Nullable<Int4>,
        address -> Nullable<Text>,
        city -> Nullable<Text>,
        description -> Nullable<Text>,
    }
}

diesel::table! {
    packet (id) {
        id -> Int8,
        probe_id -> Uuid,
        src_mac -> Macaddr,
        dst_mac -> Macaddr,
        src_addr -> Cidr,
        dst_addr -> Cidr,
        src_port -> Int4,
        dst_port -> Int4,
        payload -> Bytea,
        payload_hash -> Int8,
        payload_string -> Nullable<Text>,
        captured_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    packet_transmit_request (id) {
        id -> Int8,
        device_id -> Int8,
        user_id -> Int8,
        target_ip -> Cidr,
        target_port -> Int4,
        permanent -> Bool,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    probe (id) {
        id -> Uuid,
        owner_id -> Nullable<Int8>,
        location_id -> Nullable<Int8>,
        adopted -> Bool,
        mac -> Macaddr,
        ip -> Cidr,
        name -> Nullable<Text>,
        pre_shared_key -> Nullable<Text>,
        first_connected_at -> Nullable<Timestamptz>,
        last_connected_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    probe_config (id) {
        id -> Int8,
        probe_id -> Uuid,
        interface -> Text,
        filter -> Nullable<Text>,
    }
}

diesel::table! {
    user (id) {
        id -> Int8,
        email -> Text,
        name -> Text,
        surname -> Text,
        password_hash -> Nullable<Text>,
        password_salt -> Nullable<Text>,
        admin -> Bool,
        disabled -> Bool,
        created_at -> Timestamptz,
        edited_at -> Timestamptz,
        deleted_at -> Nullable<Timestamptz>,
    }
}

diesel::joinable!(device -> probe (probe_id));
diesel::joinable!(group_probe_permission -> group (group_id));
diesel::joinable!(group_probe_permission -> probe (probe_id));
diesel::joinable!(group_user -> group (group_id));
diesel::joinable!(group_user -> user (user_id));
diesel::joinable!(packet -> probe (probe_id));
diesel::joinable!(packet_transmit_request -> device (device_id));
diesel::joinable!(packet_transmit_request -> user (user_id));
diesel::joinable!(probe -> location (location_id));
diesel::joinable!(probe -> user (owner_id));
diesel::joinable!(probe_config -> probe (probe_id));

diesel::allow_tables_to_appear_in_same_query!(
    device,
    group,
    group_probe_permission,
    group_user,
    location,
    packet,
    packet_transmit_request,
    probe,
    probe_config,
    user,
);
