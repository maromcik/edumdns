use diesel::result::DatabaseErrorKind;
use std::fmt::{Debug};
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum DbError {
    #[error("Backend error -> {0}")]
    BackendError(#[from] BackendError),
    #[error("database error: {0}")]
    DatabaseError(String),
    #[error("migration error: {0}")]
    MigrationError(String),
    #[error("unique constraint error: {0}")]
    UniqueConstraintError(String),
    #[error("not null error: {0}")]
    NotNullError(String),
    #[error("foreign key error: {0}")]
    ForeignKeyError(String),
    #[error("database connection error: {0}")]
    ConnectionError(String),
    #[error("database pool (build) error: {0}")]
    DbPoolError(String),
}

impl From<diesel::result::Error> for DbError {
    fn from(error: diesel::result::Error) -> Self {
        match error {
            diesel::result::Error::NotFound => DbError::BackendError(BackendError::DoesNotExist(error.to_string())),
            diesel::result::Error::DatabaseError(err, err_info) => match err {
                DatabaseErrorKind::UniqueViolation => DbError::UniqueConstraintError(err_info.message().to_string()),
                DatabaseErrorKind::ForeignKeyViolation => DbError::ForeignKeyError(err_info.message().to_string()),
                DatabaseErrorKind::NotNullViolation => DbError::NotNullError(err_info.message().to_string()),
                _ => DbError::DatabaseError(err_info.message().to_string()),
            },
            err => DbError::DatabaseError(err.to_string())
        }
    }
}

impl From<diesel::ConnectionError> for DbError {
    fn from(value: diesel::ConnectionError) -> Self {
        Self::ConnectionError(value.to_string())
    }
}

impl From<diesel_async::pooled_connection::deadpool::BuildError> for DbError {
    fn from(value: diesel_async::pooled_connection::deadpool::BuildError) -> Self {
        Self::DbPoolError(value.to_string())
    }
}

impl From<diesel_async::pooled_connection::PoolError> for DbError {
    fn from(value: diesel_async::pooled_connection::PoolError) -> Self {
        Self::DbPoolError(value.to_string())
    }
}

impl From<diesel_async::pooled_connection::deadpool::PoolError> for DbError {
    fn from(value: diesel_async::pooled_connection::deadpool::PoolError) -> Self {
        Self::DbPoolError(value.to_string())
    }
}

impl From<pbkdf2::password_hash::Error> for DbError {
    fn from(value: pbkdf2::password_hash::Error) -> Self {
        Self::BackendError(BackendError::UserPasswordVerificationFailed(value.to_string()))
    }
}

#[derive(Debug, Clone, Error)]
pub enum BackendError {
    // User errors
    #[error("entity does not exist: {0}")]
    DoesNotExist(String),
    #[error("entity has been deleted")]
    Deleted,
    #[error("update parameters are empty")]
    UpdateParametersEmpty,
    #[error("the provided email and password combination is incorrect.")]
    UserPasswordDoesNotMatch,
    #[error("password verification failed: {0}")]
    UserPasswordVerificationFailed(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
}