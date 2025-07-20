use minijinja::{path_loader, Environment};
use minijinja_autoreload::AutoReloader;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub jinja: Arc<AutoReloader>,
}

impl AppState {
    pub fn new(jinja: Arc<AutoReloader>) -> Self {
        AppState { jinja, }
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

