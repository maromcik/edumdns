use minijinja::{Environment, path_loader};
use minijinja_autoreload::AutoReloader;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use edumdns_core::app_packet::AppPacket;

#[derive(Clone)]
pub struct AppState {
    pub jinja: Arc<AutoReloader>,
    pub command_channel: Sender<AppPacket>
}

impl AppState {
    pub fn new(jinja: Arc<AutoReloader>, command_channel: Sender<AppPacket>) -> Self {
        AppState { jinja, command_channel }
    }
}

pub fn create_reloader(template_path: String) -> AutoReloader {
    AutoReloader::new(move |notifier| {
        let mut env = Environment::new();
        env.set_loader(path_loader(&template_path));
        notifier.set_fast_reload(true);
        notifier.watch_path(&template_path, true);
        Ok(env)
    })
}
