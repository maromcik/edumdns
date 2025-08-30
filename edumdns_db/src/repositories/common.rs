use crate::error::DbError;
use diesel::backend::Backend;
use diesel::deserialize::FromSql;
use diesel::serialize::{Output, ToSql};
use diesel::sql_types::SmallInt;
use diesel::{deserialize, serialize, AsExpression, FromSqlRow};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use uuid::Uuid;
use crate::repositories::probe::models::SelectSingleProbe;

const PAGINATION_ELEMENTS_PER_PAGE: i64 = 20;

pub type Id = i64;
pub type Permissions = Vec<Permission>;

pub type DbResult<T> = Result<T, DbError>;

/// Syntax sugar type denoting a singular result from the database
pub type DbResultSingle<T> = DbResult<T>;
/// Syntax sugar type denoting multiple results from the database
pub type DbResultMultiple<T> = DbResult<Vec<T>>;

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

pub trait EntityWithId {
    type EntityId;
    type UserId;

    fn get_id(&self) -> Self::EntityId;
    fn get_user_id(&self) -> Self::UserId;
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct SelectSingleById {
    pub user_id: Id,
    pub id: Id,
}

impl SelectSingleById {
    pub fn new(user_id: Id, id: Id) -> Self {
        Self { user_id, id}

    }
}

impl EntityWithId for SelectSingleById {
    type EntityId = Id;
    type UserId = Id;

    fn get_id(&self) -> Self::EntityId {
        self.id
    }

    fn get_user_id(&self) -> Self::UserId {
        self.user_id
    }
}

#[repr(i16)]
#[derive(AsExpression, Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize, FromSqlRow)]
#[diesel(sql_type = SmallInt)]
pub enum Permission {
    Read,
    Adopt,
    Forget,
    Restart,
    ModifyConfig,
    Delete,
    Update,
    Full,
}

impl Display for Permission {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Permission::Read => write!(f, "read"),
            Permission::Adopt => write!(f, "adopt"),
            Permission::Forget => write!(f, "forget"),
            Permission::Restart => write!(f, "restart"),
            Permission::ModifyConfig => write!(f, "modify_config"),
            Permission::Delete => write!(f, "delete"),
            Permission::Update => write!(f, "update"),
            Permission::Full => write!(f, "full"),
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
            0 => Ok(Permission::Read),
            1 => Ok(Permission::Adopt),
            2 => Ok(Permission::Forget),
            3 => Ok(Permission::Restart),
            4 => Ok(Permission::ModifyConfig),
            5 => Ok(Permission::Delete),
            6 => Ok(Permission::Update),
            7 => Ok(Permission::Full),
            x => Err(format!("Unrecognized variant {}", x).into())
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
            Permission::Read => 0_i16.to_sql(out),
            Permission::Adopt => 1_i16.to_sql(out),
            Permission::Forget => 2_i16.to_sql(out),
            Permission::Restart => 3_i16.to_sql(out),
            Permission::ModifyConfig => 4_i16.to_sql(out),
            Permission::Delete => 5_i16.to_sql(out),
            Permission::Update => 6_i16.to_sql(out),
            Permission::Full => 7_i16.to_sql(out),
        }
    }
}

