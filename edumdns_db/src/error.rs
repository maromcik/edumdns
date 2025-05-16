// use edumdns_core::error::CoreError;
// use std::fmt::{Debug, Display, Formatter};
// use thiserror::Error;
//
// #[derive(Error, Debug, Clone)]
// pub enum DbErrorKind {
//     CoreError(CoreError),
//     DatabaseError,
//     MigrationError,
//     UniqueConstraintError,
//     NotNullError,
//     ForeignKeyError,
//     DatabasePoolConnectionError,
// }
//
// impl Display for DbErrorKind {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         match self {
//             DbErrorKind::CoreError(err) => std::fmt::Display::fmt(&err, f),
//             DbErrorKind::DatabaseError => write!(f, "database error"),
//             DbErrorKind::DatabasePoolConnectionError => write!(f, "database pool connection error"),
//             DbErrorKind::MigrationError => write!(f, "migration error"),
//             DbErrorKind::UniqueConstraintError => write!(f, "broken unique constraint"),
//             DbErrorKind::NotNullError => write!(f, "")
//             DbErrorKind::ForeignKeyError => {}
//         }
//     }
// }
//
// #[derive(Error, Debug, Clone)]
// pub struct DbError {
//     pub error_kind: DbErrorKind,
//     pub message: String,
// }
//
// impl Display for DbError {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         write!(f, "ProbeError: {}: {}", self.error_kind, self.message)
//     }
// }
//
// impl DbError {
//     pub fn new(error_kind: DbErrorKind, message: &str) -> Self {
//         Self {
//             error_kind,
//             message: message.to_owned(),
//         }
//     }
// }
//
// impl From<CoreError> for DbError {
//     fn from(value: CoreError) -> Self {
//         Self::new(
//             DbErrorKind::CoreError(value),
//             ""
//         )
//     }
// }
//
// // impl From<diesel::result::Error> for DbError {
// //     fn from(error: diesel::result::Error) -> Self {
// //         match error {
// //             diesel::result::Error::NotFound => DbError::new(DbErrorKind::DatabaseError, )
// //             err => DatabaseError::Error(err),
// //         }
// //     }
// // }