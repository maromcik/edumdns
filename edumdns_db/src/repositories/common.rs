use edumdns_core::app_packet::Id;
use crate::error::DbError;
use crate::models::GroupProbePermission;
use diesel::backend::Backend;
use diesel::deserialize::FromSql;
use diesel::serialize::{Output, ToSql};
use diesel::sql_types::SmallInt;
use diesel::{AsExpression, FromSqlRow, deserialize, serialize};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use strum_macros::EnumIter;

pub const PAGINATION_ELEMENTS_PER_PAGE: i64 = 10;

pub type Permissions = Vec<GroupProbePermission>;

pub type DbResult<T> = Result<T, DbError>;

pub type DbResultPerm<T> = Result<DbDataPerm<T>, DbError>;

/// Syntax sugar type denoting a singular result from the database
pub type DbResultSingle<T> = DbResult<T>;
/// Syntax sugar type denoting multiple results from the database
pub type DbResultMultiple<T> = DbResult<Vec<T>>;

/// Syntax sugar type denoting a singular result from the database with permissions
pub type DbResultSinglePerm<T> = DbResultPerm<T>;
/// Syntax sugar type denoting multiple results from the database with permissions
pub type DbResultMultiplePerm<T> = DbResultPerm<Vec<T>>;

pub struct DbDataPerm<T> {
    pub data: T,
    pub admin: bool,
    pub permissions: Permissions,
}

impl<T> DbDataPerm<T> {
    pub fn new(data: T, (admin, permissions): (bool, Permissions)) -> Self {
        Self {
            data,
            admin,
            permissions,
        }
    }
}

pub trait DbCreate<Create, Data> {
    /// Generic call which creates a record in the database
    ///
    /// # Arguments
    ///
    /// - `self`: mutable reference to the repository to access the pool handler
    /// - `data`: the structure which passes all the data that is necessary for creation of the
    ///         record in the database
    ///
    /// # Returns
    ///
    /// - `Ok(Data)` on success (the provided structure which represents
    ///                          data coming from the database)
    /// - `sqlx::Error(_)` on any failure (SQL, DB constraints, connection, etc.)
    fn create(&self, data: &Create) -> impl Future<Output = DbResultSingle<Data>> + Send;
    fn create_auth(
        &self,
        data: &Create,
        user_id: &Id,
    ) -> impl Future<Output = DbResultSingle<Data>> + Send;
}

pub trait DbReadOne<ReadOne, Data> {
    /// Generic call which reads a single record from the database
    ///
    /// # Arguments
    ///
    /// - `self`: mutable reference to the repository to access the pool handler
    /// - `params`: the structure which passes parameters for the read operation
    ///
    /// # Returns
    ///
    /// - `Ok(Data)` on success (the provided structure which represents read data coming
    ///                          from the database)
    /// - `sqlx::Error(_)` on any failure (SQL, DB constraints, connection, etc.)
    fn read_one(&self, params: &ReadOne) -> impl Future<Output = DbResultSingle<Data>> + Send;
    fn read_one_auth(
        &self,
        params: &ReadOne,
        user_id: &Id,
    ) -> impl Future<Output = DbResultSinglePerm<Data>> + Send;
}

pub trait DbReadMany<ReadMany, Data> {
    /// Generic call which reads multiple records from the database
    ///
    /// # Arguments
    ///
    /// - `self`: mutable reference to the repository to access the pool handler
    /// - `params`: the structure which passes parameters for the read operation
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<Data>)` on success (a vector of structures which represent read data from the
    ///                               database)
    /// - `sqlx::Error(_)` on any failure (SQL, DB constraints, connection, etc.)
    fn read_many(&self, params: &ReadMany) -> impl Future<Output = DbResultMultiple<Data>> + Send;
    fn read_many_auth(
        &self,
        params: &ReadMany,
        user_id: &Id,
    ) -> impl Future<Output = DbResultMultiplePerm<Data>> + Send;
}

pub trait DbUpdate<Update, Data> {
    /// Generic call which updates record(s) present in the database
    ///
    /// # Arguments
    ///
    /// - `self`: mutable reference to the repository to access the pool handler
    /// - `params`: the structure which passes parameters for the update operation
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<Data>)` on success (a vector of structures which represent updated data from the
    ///                               database)
    /// - `sqlx::Error(_)` on any failure (SQL, DB constraints, connection, etc.)
    fn update(&self, params: &Update) -> impl Future<Output = DbResultMultiple<Data>> + Send;

    fn update_auth(
        &self,
        params: &Update,
        user_id: &Id,
    ) -> impl Future<Output = DbResultMultiple<Data>> + Send;
}

pub trait DbDelete<Delete, Data> {
    /// Generic call which deletes record(s) present in the database
    ///
    /// # Arguments
    ///
    /// - `self`: mutable reference to the repository to access the pool handler
    /// - `params`: the structure which passes parameters for the delete operation
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<Data>)` on success (a vector of structures which represent deleted data from the
    ///                               database)
    /// - `sqlx::Error(_)` on any failure (SQL, DB constraints, connection, etc.)
    fn delete(&self, params: &Delete) -> impl Future<Output = DbResultMultiple<Data>> + Send;
    fn delete_auth(
        &self,
        params: &Delete,
        user_id: &Id,
    ) -> impl Future<Output = DbResultMultiple<Data>> + Send;
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct Pagination {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl Pagination {
    pub fn new(limit: Option<i64>, offset: Option<i64>) -> Self {
        Self { limit, offset }
    }
    pub fn default_pagination(page: Option<i64>) -> Self {
        Self {
            limit: Some(PAGINATION_ELEMENTS_PER_PAGE),
            offset: Some((page.unwrap_or(1) - 1) * PAGINATION_ELEMENTS_PER_PAGE),
        }
    }
}
#[repr(i16)]
#[derive(
    AsExpression,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Copy,
    Serialize,
    Deserialize,
    FromSqlRow,
    EnumIter,
    Hash,
)]
#[diesel(sql_type = SmallInt)]
pub enum Permission {
    Full,
    Read,
    Adopt,
    Forget,
    Reconnect,
    ModifyConfig,
    Delete,
    Update,
    Create,
}

impl Permission {
    pub fn web() -> Vec<Permission> {
        vec![
            Permission::Read,
            Permission::Delete,
            Permission::Update,
            Permission::Create,
        ]
    }

    pub fn admin() -> Vec<Permission> {
        vec![Permission::Full]
    }
}

impl Display for Permission {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Permission::Full => write!(f, "Full"),
            Permission::Read => write!(f, "Read"),
            Permission::Adopt => write!(f, "Adopt"),
            Permission::Forget => write!(f, "Forget"),
            Permission::Reconnect => write!(f, "Reconnect"),
            Permission::ModifyConfig => write!(f, "ModifyConfig"),
            Permission::Delete => write!(f, "Delete"),
            Permission::Update => write!(f, "Update"),
            Permission::Create => write!(f, "Create"),
        }
    }
}

impl<DB> FromSql<SmallInt, DB> for Permission
where
    DB: Backend,
    i16: FromSql<SmallInt, DB>,
{
    fn from_sql(bytes: DB::RawValue<'_>) -> deserialize::Result<Self> {
        match i16::from_sql(bytes)? {
            0 => Ok(Permission::Full),
            1 => Ok(Permission::Read),
            2 => Ok(Permission::Adopt),
            3 => Ok(Permission::Forget),
            4 => Ok(Permission::Reconnect),
            5 => Ok(Permission::ModifyConfig),
            6 => Ok(Permission::Delete),
            7 => Ok(Permission::Update),
            8 => Ok(Permission::Create),
            x => Err(format!("Unrecognized variant {}", x).into()),
        }
    }
}

impl<DB> ToSql<SmallInt, DB> for Permission
where
    DB: Backend,
    i16: ToSql<SmallInt, DB>,
{
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, DB>) -> serialize::Result {
        match *self {
            Permission::Full => 0_i16.to_sql(out),
            Permission::Read => 1_i16.to_sql(out),
            Permission::Adopt => 2_i16.to_sql(out),
            Permission::Forget => 3_i16.to_sql(out),
            Permission::Reconnect => 4_i16.to_sql(out),
            Permission::ModifyConfig => 5_i16.to_sql(out),
            Permission::Delete => 6_i16.to_sql(out),
            Permission::Update => 7_i16.to_sql(out),
            Permission::Create => 8_i16.to_sql(out),
        }
    }
}
