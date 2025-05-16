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
    #[error("DB pool error")]
    DatabasePoolConnectionError,
}

#[derive(Error, Debug, Clone)]
pub struct DbError {
    pub error_kind: DbErrorKind,
    pub message: String,
}

impl Display for DbError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProbeError: {}: {}", self.error_kind, self.message)
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
            diesel::result::Error::NotFound => DbError::new(DbErrorKind::DatabaseError, error.to_string().as_str()),

            err => DbError::new(DbErrorKind::DatabaseError, err.to_string().as_str()),
        }
    }
}

impl From<BackendError> for DbError {
    fn from(value: BackendError) -> Self {
        Self::new(
            DbErrorKind::BackendError(value),
            "",
        )
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
        Self { error_kind: error, message }
    }

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "BackendError: {}: {}", self.message, self.error_kind)
    }
}

impl Display for BackendError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.fmt(f)
    }
}