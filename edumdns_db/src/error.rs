use diesel::result::DatabaseErrorKind;
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum DbErrorKind {
    #[error("{0}")]
    BackendError(#[from] BackendError),
    #[error("Database error")]
    DatabaseError,
    #[error("Migration error")]
    MigrationError,
    #[error("Unique constraint error")]
    UniqueConstraintError,
    #[error("Not null error")]
    NotNullError,
    #[error("Foreign key error")]
    ForeignKeyError,
    #[error("Database connection error")]
    ConnectionError,
    #[error("Database pool (build) error")]
    DbPoolError,
}

#[derive(Error, Debug, Clone)]
pub struct DbError {
    pub error_kind: DbErrorKind,
    pub message: String,
}

impl Display for DbError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.error_kind {
            DbErrorKind::BackendError(e) => write!(f, "DbError -> {}", e),
            _ => write!(f, "DbError: {}: {}", self.error_kind, self.message),
        }
    }
}
impl DbError {
    pub fn new(error_kind: DbErrorKind, message: &str) -> Self {
        Self {
            error_kind,
            message: message.to_owned(),
        }
    }
}

impl From<diesel::result::Error> for DbError {
    fn from(error: diesel::result::Error) -> Self {
        match error {
            diesel::result::Error::NotFound => DbError::new(
                DbErrorKind::BackendError(BackendError::new(
                    BackendErrorKind::DoesNotExist,
                    "".to_string(),
                )),
                error.to_string().as_str(),
            ),
            diesel::result::Error::DatabaseError(err, err_info) => match err {
                DatabaseErrorKind::UniqueViolation => {
                    DbError::new(DbErrorKind::UniqueConstraintError, err_info.message())
                }
                DatabaseErrorKind::ForeignKeyViolation => {
                    DbError::new(DbErrorKind::ForeignKeyError, err_info.message())
                }
                DatabaseErrorKind::NotNullViolation => {
                    DbError::new(DbErrorKind::NotNullError, err_info.message())
                }
                _ => DbError::new(DbErrorKind::DatabaseError, err_info.message()),
            },
            err => DbError::new(DbErrorKind::DatabaseError, err.to_string().as_str()),
        }
    }
}

impl From<diesel::ConnectionError> for DbError {
    fn from(value: diesel::ConnectionError) -> Self {
        Self::new(DbErrorKind::ConnectionError, value.to_string().as_str())
    }
}

impl From<diesel_async::pooled_connection::deadpool::BuildError> for DbError {
    fn from(value: diesel_async::pooled_connection::deadpool::BuildError) -> Self {
        Self::new(DbErrorKind::DbPoolError, value.to_string().as_str())
    }
}

impl From<diesel_async::pooled_connection::PoolError> for DbError {
    fn from(value: diesel_async::pooled_connection::PoolError) -> Self {
        Self::new(DbErrorKind::DbPoolError, value.to_string().as_str())
    }
}

impl From<diesel_async::pooled_connection::deadpool::PoolError> for DbError {
    fn from(value: diesel_async::pooled_connection::deadpool::PoolError) -> Self {
        Self::new(DbErrorKind::DbPoolError, value.to_string().as_str())
    }
}

impl From<BackendError> for DbError {
    fn from(value: BackendError) -> Self {
        Self::new(DbErrorKind::BackendError(value), "")
    }
}

#[derive(Debug, Clone, Error)]
pub enum BackendErrorKind {
    // User errors
    #[error("entity does not exist")]
    DoesNotExist,
    #[error("entity has been deleted")]
    Deleted,
    #[error("update parameters are empty")]
    UpdateParametersEmpty,
    #[error("The provided email and password combination is incorrect.")]
    UserPasswordDoesNotMatch,
}

#[derive(Clone, Debug, Error)]
pub struct BackendError {
    pub error_kind: BackendErrorKind,
    pub message: String,
}

impl BackendError {
    #[must_use]
    #[inline]
    pub const fn new(error: BackendErrorKind, message: String) -> Self {
        Self {
            error_kind: error,
            message,
        }
    }

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "BackendError: {}: {}", self.message, self.error_kind)
    }
}

impl Display for BackendError{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Backend Error: {}: {}", self.error_kind, self.message)
    }
}