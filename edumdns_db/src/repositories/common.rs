use crate::error::DbError;
use serde::{Deserialize, Serialize};

const PAGINATION_ELEMENTS_PER_PAGE: i64 = 20;

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

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct GetById {
    pub id: Id,
}

impl GetById {
    pub fn new(id: Id) -> Self {
        Self { id }
    }
}

pub type Id = i64;
