use edumdns_core::app_packet::AppPacket;
use edumdns_db::models::GroupProbePermission;
use edumdns_db::repositories::common::Permission;
use minijinja::{Environment, Value, path_loader};
use minijinja_autoreload::AutoReloader;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

#[derive(Clone)]
pub struct DeviceAclApDatabase {
    pub connection_string: String,
    pub query: String,
}

#[derive(Clone)]
pub struct AppState {
    pub jinja: Arc<AutoReloader>,
    pub command_channel: Sender<AppPacket>,
    pub device_acl_ap_database: DeviceAclApDatabase,
}

impl AppState {
    pub fn new(
        jinja: Arc<AutoReloader>,
        command_channel: Sender<AppPacket>,
        device_acl_ap_database: DeviceAclApDatabase,
    ) -> Self {
        AppState {
            jinja,
            command_channel,
            device_acl_ap_database,
        }
    }
}

pub fn create_reloader(template_path: String) -> AutoReloader {
    AutoReloader::new(move |notifier| {
        let mut env = Environment::new();
        env.set_loader(path_loader(&template_path));
        env.add_filter("has_perm", has_perm);
        notifier.set_fast_reload(true);
        notifier.watch_path(&template_path, true);
        Ok(env)
    })
}

fn has_perm(perms_values: Vec<Value>, query: Value) -> Result<bool, minijinja::Error> {
    let query_perm = Permission::deserialize(query)?;
    for perm in perms_values {
        let perm = GroupProbePermission::deserialize(perm)?;
        if perm.permission == query_perm || perm.permission == Permission::Full {
            return Ok(true);
        }
    }
    Ok(false)
}
