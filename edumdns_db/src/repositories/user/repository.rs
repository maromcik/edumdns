use crate::error::{BackendError, BackendErrorKind, DbError, DbErrorKind};
use crate::models::User;
use crate::repositories::common::{
    DbDataPerm, DbReadMany, DbReadOne, DbResultMultiple, DbResultMultiplePerm, DbResultSingle,
    DbResultSinglePerm, Id,
};

use crate::error::BackendErrorKind::UserPasswordDoesNotMatch;
use crate::repositories::user::models::{SelectManyUsers, UserLogin};
use crate::schema::user::{admin, deleted_at, email, name, surname};
use diesel::{ExpressionMethods, JoinOnDsl, PgTextExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::deadpool::Pool;
use pbkdf2::Pbkdf2;
use pbkdf2::password_hash::rand_core::OsRng;
use pbkdf2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use crate::repositories::utilities::validate_admin;
use crate::schema::group_user;
use crate::schema::user;

fn generate_salt() -> SaltString {
    SaltString::generate(&mut OsRng)
}

fn hash_password(password: String, salt: &SaltString) -> Result<String, DbError> {
    let password_hash = Pbkdf2.hash_password(password.as_bytes(), salt)?.to_string();
    Ok(password_hash)
}

fn verify_password_hash(
    expected_password_hash: &str,
    password_candidate: &str,
) -> Result<bool, DbError> {
    let parsed_hash = PasswordHash::new(expected_password_hash)?;
    let bytes = password_candidate.bytes().collect::<Vec<u8>>();
    Ok(Pbkdf2.verify_password(&bytes, &parsed_hash).is_ok())
}

#[derive(Clone)]
pub struct PgUserRepository {
    pg_pool: Pool<AsyncPgConnection>,
}

impl PgUserRepository {
    pub fn new(pg_pool: Pool<AsyncPgConnection>) -> Self {
        Self { pg_pool }
    }

    pub async fn login(&self, params: &UserLogin) -> DbResultSingle<User> {
        let mut conn = self.pg_pool.get().await?;
        let u = user::table
            .filter(email.eq(&params.email))
            .first::<User>(&mut conn)
            .await?;
        if u.deleted_at.is_some() {
            return Err(DbError::new(
                DbErrorKind::BackendError(BackendError::new(
                    BackendErrorKind::Deleted,
                    "User has been deleted",
                )),
                "",
            ));
        }
        PgUserRepository::verify_password(u, &params.password)
    }

    pub fn verify_password(u: User, given_password: &str) -> DbResultSingle<User> {
        match verify_password_hash(&u.password_hash, given_password) {
            Ok(ret) => {
                if ret {
                    return Ok(u);
                }
                Err(DbError::from(BackendError::new(
                    UserPasswordDoesNotMatch,
                    "",
                )))
            }
            Err(e) => Err(e),
        }
    }
}

impl DbReadOne<Id, User> for PgUserRepository {
    async fn read_one(&self, params: &Id) -> DbResultSingle<User> {
        let mut conn = self.pg_pool.get().await?;
        let u = user::table.find(&params).first::<User>(&mut conn).await?;
        Ok(u)
    }

    async fn read_one_auth(&self, params: &Id, user_id: &Id) -> DbResultSinglePerm<User> {
        let u = self.read_one(params).await?;
        Ok(DbDataPerm::new(u, (false, vec![])))
    }
}


impl DbReadMany<SelectManyUsers, User> for PgUserRepository {
    async fn read_many(&self, params: &SelectManyUsers) -> DbResultMultiple<User> {
        let mut query = user::table.into_boxed();

        if let Some(n) = &params.name {
            query = query.filter(name.eq(n));
        }

        if let Some(s) = &params.surname {
            query = query.filter(surname.eq(s));
        }

        if let Some(e) = &params.email {
            query = query.filter(email.eq(e));
        }

        if let Some(a) = &params.admin {
            query = query.filter(admin.eq(a));
        }

        if let Some(d) = &params.deleted {
            if *d {
                query = query.filter(deleted_at.is_not_null());
            } else {
                query = query.filter(deleted_at.is_null());
            }
        }

        if let Some(pagination) = params.pagination {
            query = query.limit(pagination.limit.unwrap_or(i64::MAX));
            query = query.offset(pagination.offset.unwrap_or(0));
        }

        let mut conn = self.pg_pool.get().await?;
        let users = query.load::<User>(&mut conn).await?;

        Ok(users)
    }

    async fn read_many_auth(
        &self,
        params: &SelectManyUsers,
        user_id: &Id,
    ) -> DbResultMultiplePerm<User> {
        let users = self.read_many(params).await?;
        Ok(DbDataPerm::new(users, (false, vec![])))
    }
}
