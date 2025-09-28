use crate::error::{BackendError, BackendErrorKind, DbError, DbErrorKind};
use crate::models::{GroupUser, User};
use crate::repositories::common::{
    DbCreate, DbDataPerm, DbDelete, DbReadMany, DbReadOne, DbResultMultiple, DbResultMultiplePerm,
    DbResultSingle, DbResultSinglePerm, DbUpdate, Id,
};

use crate::error::BackendErrorKind::UserPasswordDoesNotMatch;
use crate::repositories::user::models::{
    SelectManyUsers, UserCreate, UserLogin, UserUpdate, UserUpdatePassword,
};
use crate::repositories::utilities::{
    generate_salt, hash_password, validate_admin, verify_password_hash,
};
use crate::schema::{group_user, user};
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, AsyncPgConnection};

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
            .filter(user::email.eq(&params.email))
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
        let Some(hash) = &u.password_hash else {
            return Err(DbError::from(BackendError::new(
                UserPasswordDoesNotMatch,
                "",
            )));
        };
        match verify_password_hash(hash, given_password) {
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

    pub async fn update_password(&self, params: &UserUpdatePassword) -> DbResultSingle<User> {
        let mut conn = self.pg_pool.get().await?;

        let user = conn
            .transaction::<_, DbError, _>(|c| {
                async move {
                    let u = user::table.find(&params.id).first::<User>(c).await?;

                    let u = PgUserRepository::verify_password(u, &params.old_password)?;

                    let salt = generate_salt();
                    let password_hash = hash_password(params.new_password.clone(), &salt)?;

                    diesel::update(&u)
                        .set((
                            user::password_hash.eq(password_hash),
                            user::password_salt.eq(salt.to_string()),
                        ))
                        .execute(c)
                        .await?;

                    Ok::<User, DbError>(u)
                }
                .scope_boxed()
            })
            .await?;
        Ok(user)
    }

    pub async fn get_groups(&self, user_id: &Id) -> DbResultMultiple<GroupUser> {
        let mut conn = self.pg_pool.get().await?;
        let maps = group_user::table
            .filter(group_user::user_id.eq(user_id))
            .select(GroupUser::as_select())
            .load::<GroupUser>(&mut conn)
            .await?;
        Ok(maps)
    }
}

impl DbReadOne<Id, User> for PgUserRepository {
    async fn read_one(&self, params: &Id) -> DbResultSingle<User> {
        let mut conn = self.pg_pool.get().await?;
        let u = user::table.find(&params).first::<User>(&mut conn).await?;
        Ok(u)
    }

    async fn read_one_auth(&self, params: &Id, user_id: &Id) -> DbResultSinglePerm<User> {
        validate_admin(&self.pg_pool, user_id).await?;
        let u = self.read_one(params).await?;
        Ok(DbDataPerm::new(u, (false, vec![])))
    }
}

impl DbReadMany<SelectManyUsers, User> for PgUserRepository {
    async fn read_many(&self, params: &SelectManyUsers) -> DbResultMultiple<User> {
        let mut query = user::table.into_boxed();

        if let Some(id) = &params.id {
            query = query.filter(user::id.eq(id));
        }

        if let Some(n) = &params.name {
            query = query.filter(user::name.eq(n));
        }

        if let Some(s) = &params.surname {
            query = query.filter(user::surname.eq(s));
        }

        if let Some(e) = &params.email {
            query = query.filter(user::email.eq(e));
        }

        if let Some(a) = &params.admin {
            query = query.filter(user::admin.eq(a));
        }

        if let Some(d) = &params.disabled {
            query = query.filter(user::disabled.eq(d));
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
        validate_admin(&self.pg_pool, user_id).await?;
        let users = self.read_many(params).await?;
        Ok(DbDataPerm::new(users, (false, vec![])))
    }
}

impl DbUpdate<UserUpdate, User> for PgUserRepository {
    async fn update(&self, params: &UserUpdate) -> DbResultMultiple<User> {
        let mut conn = self.pg_pool.get().await?;
        let updated_users = diesel::update(user::table.find(&params.id))
            .set(params)
            .get_results(&mut conn)
            .await?;
        Ok(updated_users)
    }

    async fn update_auth(&self, params: &UserUpdate, user_id: &Id) -> DbResultMultiple<User> {
        validate_admin(&self.pg_pool, user_id).await?;
        self.update(params).await
    }
}

impl DbCreate<UserCreate, User> for PgUserRepository {
    async fn create(&self, data: &UserCreate) -> DbResultSingle<User> {
        let mut conn = self.pg_pool.get().await?;
        diesel::insert_into(user::table)
            .values(data)
            .on_conflict(user::id)
            .do_update()
            .set((
                user::email.eq(&data.email),
                user::name.eq(&data.name),
                user::surname.eq(&data.surname),
            ))
            .returning(User::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }

    async fn create_auth(&self, data: &UserCreate, user_id: &Id) -> DbResultSingle<User> {
        validate_admin(&self.pg_pool, user_id).await?;
        self.create(data).await
    }
}

impl DbDelete<Id, User> for PgUserRepository {
    async fn delete(&self, params: &Id) -> DbResultMultiple<User> {
        let mut conn = self.pg_pool.get().await?;
        diesel::delete(user::table.find(params))
            .get_results(&mut conn)
            .await
            .map_err(DbError::from)
    }

    async fn delete_auth(&self, params: &Id, user_id: &Id) -> DbResultMultiple<User> {
        validate_admin(&self.pg_pool, user_id).await?;
        self.delete(params).await
    }
}
