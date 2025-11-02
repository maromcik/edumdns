use crate::templates::error::GenericError;
use actix_web::http::StatusCode;
use actix_web::http::header::ContentType;
use actix_web::{HttpResponse, ResponseError};
use edumdns_core::error::CoreError;
use edumdns_db::error::{BackendError, DbError};
use edumdns_server::error::ServerError;
use minijinja::{Environment, path_loader};
use std::env;
use std::error::Error;
use std::fmt::Debug;
use std::num::ParseIntError;
use std::str::ParseBoolError;
use thiserror::Error;
use tokio::task::JoinError;

/// User facing error type
#[derive(Error, Clone)]
pub enum WebError {
    #[error("CoreError -> {0}")]
    CoreError(CoreError),
    #[error("DbError -> {0}")]
    DbError(DbError),
    #[error("ServerError -> {0}")]
    ServerError(ServerError),
    #[error("Internal server error: {0}")]
    InternalServerError(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Templating error: {0}")]
    TemplatingError(String),
    #[error("Identity error: {0}")]
    IdentityError(String),
    #[error("Session error: {0}")]
    SessionError(String),
    #[error("Cookie error: {0}")]
    CookieError(String),
    #[error("File error: {0}")]
    FileError(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Device discovery request denied: {0}")]
    DeviceTransmitRequestDenied(String),
    #[error("AP database error: {0}")]
    ApDatabaseError(String),
    #[error("OIDC error: {0}")]
    OidcError(String),
    #[error("DNS packet manipulation error: {0}")]
    DnsPacketManipulationError(String),
    #[error("Could not load the env var: {0}")]
    EnvVarError(String),
}

impl Debug for WebError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{0}", self)
    }
}

impl From<CoreError> for WebError {
    fn from(value: CoreError) -> Self {
        Self::CoreError(value)
    }
}

impl From<DbError> for WebError {
    fn from(value: DbError) -> Self {
        Self::DbError(value)
    }
}

impl From<ServerError> for WebError {
    fn from(value: ServerError) -> Self {
        Self::ServerError(value)
    }
}

impl From<JoinError> for WebError {
    fn from(value: JoinError) -> Self {
        Self::InternalServerError(value.to_string())
    }
}

impl From<actix_identity::error::LoginError> for WebError {
    fn from(value: actix_identity::error::LoginError) -> Self {
        Self::IdentityError(value.to_string())
    }
}

impl From<actix_identity::error::GetIdentityError> for WebError {
    fn from(value: actix_identity::error::GetIdentityError) -> Self {
        Self::IdentityError(value.to_string())
    }
}

impl From<actix_session::SessionInsertError> for WebError {
    fn from(value: actix_session::SessionInsertError) -> Self {
        Self::SessionError(value.to_string())
    }
}

impl From<minijinja::Error> for WebError {
    fn from(value: minijinja::Error) -> Self {
        let mut res =  String::new();
        res.push_str(&value.to_string());
        while let Some(cause) = value.source() {
            res.push_str(&format!("\nCaused by: {}", cause));
        }
        Self::TemplatingError(res)
    }
}
impl From<std::io::Error> for WebError {
    fn from(value: std::io::Error) -> Self {
        Self::FileError(value.to_string())
    }
}

impl From<actix_session::SessionGetError> for WebError {
    fn from(value: actix_session::SessionGetError) -> Self {
        Self::SessionError(value.to_string())
    }
}

impl From<ParseIntError> for WebError {
    fn from(_: ParseIntError) -> Self {
        Self::IdentityError("Invalid User ID".to_string())
    }
}

impl From<ParseBoolError> for WebError {
    fn from(value: ParseBoolError) -> Self {
        Self::ParseError(value.to_string())
    }
}

impl From<actix_web::Error> for WebError {
    fn from(value: actix_web::Error) -> Self {
        Self::InternalServerError(value.to_string())
    }
}

impl From<ipnetwork::IpNetworkError> for WebError {
    fn from(value: ipnetwork::IpNetworkError) -> Self {
        Self::ParseError(value.to_string())
    }
}

impl From<env::VarError> for WebError {
    fn from(value: env::VarError) -> Self {
        Self::EnvVarError(value.to_string())
    }
}

impl From<regex::Error> for WebError {
    fn from(value: regex::Error) -> Self {
        Self::ParseError(value.to_string())
    }
}

impl From<tokio_postgres::Error> for WebError {
    fn from(value: tokio_postgres::Error) -> Self {
        Self::ApDatabaseError(value.to_string())
    }
}

impl From<serde_json::Error> for WebError {
    fn from(value: serde_json::Error) -> Self {
        Self::ParseError(value.to_string())
    }
}

impl From<hickory_proto::ProtoError> for WebError {
    fn from(value: hickory_proto::ProtoError) -> Self {
        Self::DnsPacketManipulationError(value.to_string())
    }
}

impl ResponseError for WebError {
    fn status_code(&self) -> StatusCode {
        match self {
            WebError::BadRequest(_) | WebError::ParseError(_) => StatusCode::BAD_REQUEST,
            WebError::DeviceTransmitRequestDenied(_) => StatusCode::FORBIDDEN,
            WebError::CoreError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            WebError::DbError(db_e) => match &db_e {
                DbError::BackendError(be_e) => match &be_e {
                    BackendError::DoesNotExist(_) => StatusCode::NOT_FOUND,
                    BackendError::Deleted => StatusCode::BAD_REQUEST,
                    BackendError::UpdateParametersEmpty => StatusCode::BAD_REQUEST,
                    BackendError::UserPasswordDoesNotMatch => StatusCode::UNAUTHORIZED,
                    BackendError::UserPasswordVerificationFailed(_) => StatusCode::BAD_REQUEST,
                    BackendError::PermissionDenied(_) => StatusCode::FORBIDDEN,
                },
                DbError::ForeignKeyError(_)
                | DbError::UniqueConstraintError(_)
                | DbError::NotNullError(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            WebError::ServerError(srv_e) => match srv_e {
                ServerError::DiscoveryRequestProcessingError(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            WebError::TemplatingError(_)
            | WebError::InternalServerError(_)
            | WebError::IdentityError(_)
            | WebError::SessionError(_)
            | WebError::CookieError(_)
            | WebError::FileError(_)
            | WebError::ApDatabaseError(_)
            | WebError::DnsPacketManipulationError(_)
            | WebError::EnvVarError(_)
            | WebError::OidcError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            WebError::NotFound(_) => StatusCode::NOT_FOUND,
            WebError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
        }
    }

    fn error_response(&self) -> HttpResponse {
        render_generic(self)
    }
}

fn render_generic(error: &WebError) -> HttpResponse {
    let mut env = Environment::new();
    let files_dir = env::var("EDUMDNS_FILES_DIR").unwrap_or("edumdns_web".to_string());
    env.set_loader(path_loader(format!("{files_dir}/templates")));
    let template = env
        .get_template("error.html")
        .expect("Failed to read the error template");
    let context = GenericError {
        code: error.status_code().as_u16(),
        status_code: error.status_code().to_string(),
        description: error.to_string(),
    };
    let body = template.render(context).unwrap_or_default();
    HttpResponse::build(error.status_code())
        .insert_header(ContentType::html())
        .body(body)
}
