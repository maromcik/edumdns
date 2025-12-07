use edumdns_db::error::DbError;
use edumdns_server::error::ServerError;
use edumdns_web::error::WebError;
use std::fmt::Debug;
use thiserror::Error;

#[derive(Error, Clone)]
pub enum AppError {
    #[error("DbError -> {0}")]
    DbError(DbError),
    #[error("ServerError -> {0}")]
    ServerError(ServerError),
    #[error("WebError -> {0}")]
    WebError(WebError),
    #[error("tokio error: {0}")]
    TokioError(String),
    #[error("config error: {0}")]
    ConfigError(String),
}

impl Debug for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{0}", self)
    }
}

impl From<DbError> for AppError {
    fn from(value: DbError) -> Self {
        Self::DbError(value)
    }
}

impl From<ServerError> for AppError {
    fn from(value: ServerError) -> Self {
        Self::ServerError(value)
    }
}

impl From<WebError> for AppError {
    fn from(value: WebError) -> Self {
        Self::WebError(value)
    }
}

impl From<tokio::task::JoinError> for AppError {
    fn from(value: tokio::task::JoinError) -> Self {
        Self::TokioError(value.to_string())
    }
}

impl From<config::ConfigError> for AppError {
    fn from(e: config::ConfigError) -> Self {
        Self::ConfigError(e.to_string())
    }
}
