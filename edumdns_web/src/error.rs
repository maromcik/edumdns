use crate::templates::error::GenericError;
use actix_web::http::StatusCode;
use actix_web::http::header::ContentType;
use actix_web::{HttpResponse, ResponseError};
use edumdns_core::error::{CoreError, CoreErrorKind};
use edumdns_db::error::{BackendErrorKind, DbError, DbErrorKind};
use minijinja::{Environment, path_loader};
use std::env;
use std::fmt::{Debug, Display, Formatter};
use std::num::ParseIntError;
use std::str::ParseBoolError;
use thiserror::Error;
use tokio::task::JoinError;
use edumdns_server::error::{ServerError, ServerErrorKind};

/// User facing error type
#[derive(Error, Debug, Clone)]
pub enum WebErrorKind {
    #[error("{0}")]
    CoreError(CoreError),
    #[error("{0}")]
    DbError(DbError),
    #[error("{0}")]
    ServerError(ServerError),
    #[error("internal server error")]
    InternalServerError,
    #[error("not found")]
    NotFound,
    #[error("bad request")]
    BadRequest,
    #[error("templating error")]
    TemplatingError,
    #[error("identity error")]
    IdentityError,
    #[error("session error")]
    SessionError,
    #[error("cookie error")]
    CookieError,
    #[error("conflict")]
    Conflict,
    #[error("file error")]
    FileError,
    #[error("unauthorized")]
    Unauthorized,
    #[error("email error")]
    EmailError,
    #[error("email address error")]
    EmailAddressError,
    #[error("zip error")]
    ZipError,
    #[error("parse error")]
    ParseError,
    #[error("device packet transmit request denied")]
    DeviceTransmitRequestDenied,
    #[error("env var error")]
    EnvVarError,
    #[error("AP database error")]
    ApDatabaseError,
    #[error("oidc error")]
    OidcError,
    #[error("dns packet manipulation error")]
    DnsPacketManipulationError,
}

// impl From<askama::Error> for AppError {
//     fn from(_error: askama::Error) -> Self {
//         Self::new(AppErrorKind::TemplatingError, "Templating error")
//     }
// }

#[derive(Error, Debug, Clone)]
pub struct WebError {
    pub error_kind: WebErrorKind,
    pub message: String,
}

impl WebError {
    #[must_use]
    #[inline]
    pub fn new(error: WebErrorKind, message: &str) -> Self {
        Self {
            error_kind: error,
            message: message.to_owned(),
        }
    }
}

impl Display for WebError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.error_kind {
            WebErrorKind::CoreError(e) => write!(f, "WebError -> {}", e),
            WebErrorKind::DbError(e) => write!(f, "WebError -> {}", e),
            WebErrorKind::ServerError(e) => write!(f, "WebError -> {}", e),
            _ => write!(f, "WebError: {}: {}", self.error_kind, self.message),
        }
    }
}

impl From<CoreError> for WebError {
    fn from(value: CoreError) -> Self {
        Self::new(WebErrorKind::CoreError(value), "")
    }
}

impl From<DbError> for WebError {
    fn from(value: DbError) -> Self {
        Self::new(WebErrorKind::DbError(value), "")
    }
}

impl From<ServerError> for WebError {
    fn from(value: ServerError) -> Self {
        Self::new(WebErrorKind::ServerError(value), "")
    }
}

impl From<JoinError> for WebError {
    fn from(value: JoinError) -> Self {
        Self::new(
            WebErrorKind::InternalServerError,
            value.to_string().as_str(),
        )
    }
}

impl From<actix_identity::error::LoginError> for WebError {
    fn from(value: actix_identity::error::LoginError) -> Self {
        Self::new(WebErrorKind::IdentityError, value.to_string().as_str())
    }
}

impl From<actix_identity::error::GetIdentityError> for WebError {
    fn from(value: actix_identity::error::GetIdentityError) -> Self {
        Self::new(WebErrorKind::IdentityError, value.to_string().as_str())
    }
}

impl From<actix_session::SessionInsertError> for WebError {
    fn from(value: actix_session::SessionInsertError) -> Self {
        Self::new(WebErrorKind::SessionError, value.to_string().as_str())
    }
}

impl From<minijinja::Error> for WebError {
    fn from(value: minijinja::Error) -> Self {
        Self::new(WebErrorKind::TemplatingError, value.to_string().as_str())
    }
}
impl From<std::io::Error> for WebError {
    fn from(value: std::io::Error) -> Self {
        Self::new(WebErrorKind::FileError, value.to_string().as_str())
    }
}

impl From<actix_session::SessionGetError> for WebError {
    fn from(value: actix_session::SessionGetError) -> Self {
        Self::new(WebErrorKind::SessionError, value.to_string().as_str())
    }
}

impl From<ParseIntError> for WebError {
    fn from(_: ParseIntError) -> Self {
        Self::new(WebErrorKind::IdentityError, "Invalid User ID")
    }
}

impl From<ParseBoolError> for WebError {
    fn from(value: ParseBoolError) -> Self {
        Self::new(WebErrorKind::ParseError, value.to_string().as_str())
    }
}

impl From<actix_web::Error> for WebError {
    fn from(value: actix_web::Error) -> Self {
        Self::new(
            WebErrorKind::InternalServerError,
            value.to_string().as_str(),
        )
    }
}

impl From<ipnetwork::IpNetworkError> for WebError {
    fn from(value: ipnetwork::IpNetworkError) -> Self {
        Self::new(WebErrorKind::ParseError, value.to_string().as_str())
    }
}

impl From<env::VarError> for WebError {
    fn from(value: env::VarError) -> Self {
        Self::new(WebErrorKind::EnvVarError, value.to_string().as_str())
    }
}

impl From<regex::Error> for WebError {
    fn from(value: regex::Error) -> Self {
        Self::new(WebErrorKind::ParseError, value.to_string().as_str())
    }
}

impl From<tokio_postgres::Error> for WebError {
    fn from(value: tokio_postgres::Error) -> Self {
        Self::new(WebErrorKind::ApDatabaseError, value.to_string().as_str())
    }
}

impl From<serde_json::Error> for WebError {
    fn from(value: serde_json::Error) -> Self {
        Self::new(WebErrorKind::ParseError, value.to_string().as_str())
    }
}

impl From<hickory_proto::ProtoError> for WebError {
    fn from(value: hickory_proto::ProtoError) -> Self {
        Self::new(
            WebErrorKind::DnsPacketManipulationError,
            value.to_string().as_str(),
        )
    }
}

impl ResponseError for WebError {
    fn status_code(&self) -> StatusCode {
        match self.error_kind {
            WebErrorKind::BadRequest
            | WebErrorKind::EmailAddressError
            | WebErrorKind::ParseError => StatusCode::BAD_REQUEST,
            WebErrorKind::DeviceTransmitRequestDenied => StatusCode::FORBIDDEN,
            WebErrorKind::NotFound => StatusCode::NOT_FOUND,
            WebErrorKind::Conflict => StatusCode::CONFLICT,
            WebErrorKind::Unauthorized  => StatusCode::UNAUTHORIZED,
            WebErrorKind::CoreError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            WebErrorKind::DbError(ref db_e) => match &db_e.error_kind {
                DbErrorKind::BackendError(be_e) => match &be_e.error_kind {
                    BackendErrorKind::DoesNotExist => StatusCode::NOT_FOUND,
                    BackendErrorKind::Deleted => StatusCode::BAD_REQUEST,
                    BackendErrorKind::UpdateParametersEmpty => StatusCode::BAD_REQUEST,
                    BackendErrorKind::UserPasswordDoesNotMatch => StatusCode::UNAUTHORIZED,
                    BackendErrorKind::UserPasswordVerificationFailed => StatusCode::BAD_REQUEST,
                    BackendErrorKind::PermissionDenied  => StatusCode::FORBIDDEN,
                },
                DbErrorKind::ForeignKeyError
                | DbErrorKind::UniqueConstraintError
                | DbErrorKind::NotNullError => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            WebErrorKind::ServerError(ref srv_e) => match &srv_e.error_kind {
                ServerErrorKind::PacketProcessingError(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            }
            WebErrorKind::TemplatingError
            | WebErrorKind::InternalServerError
            | WebErrorKind::IdentityError
            | WebErrorKind::SessionError
            | WebErrorKind::CookieError
            | WebErrorKind::EmailError
            | WebErrorKind::FileError
            | WebErrorKind::ZipError
            | WebErrorKind::EnvVarError
            | WebErrorKind::ApDatabaseError
            | WebErrorKind::DnsPacketManipulationError
            | WebErrorKind::OidcError => StatusCode::INTERNAL_SERVER_ERROR,
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
