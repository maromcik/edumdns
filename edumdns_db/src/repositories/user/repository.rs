use crate::error::{BackendError, BackendErrorKind, DbError, DbErrorKind};
use crate::models::{Group, GroupProbePermission, GroupUser, User};
use crate::repositories::common::{
    DbCreate, DbDataPerm, DbDelete, DbReadOne, DbResult, DbResultMultiple, DbResultSingle,
    DbResultSinglePerm, DbUpdate,
};
use edumdns_core::app_packet::Id;
use crate::error::BackendErrorKind::UserPasswordDoesNotMatch;
use crate::repositories::user::models::{
    SelectManyUsers, UserCreate, UserDisplay, UserLogin, UserUpdate, UserUpdatePassword,
};
use crate::repositories::utilities::{
    generate_salt, hash_password, validate_admin_conn, validate_user, verify_password_hash,
};
use crate::schema::user::BoxedQuery;
use crate::schema::{group, group_user, user};
use diesel::pg::Pg;
use diesel::{
    BoolExpressionMethods, ExpressionMethods, JoinOnDsl, PgTextExpressionMethods, QueryDsl,
    SelectableHelper,
};
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

    pub async fn get_user_count(&self, mut params: SelectManyUsers) -> DbResultSingle<i64> {
        let mut conn = self.pg_pool.get().await?;
        params.pagination = None;
        build_select_many_query(&params)
            .count()
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
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

    pub async fn search_user_groups(
        &self,
        params: &str,
        admin_id: &Id,
        exclude_user_id: &Id,
    ) -> DbResultMultiple<Group> {
        let mut conn = self.pg_pool.get().await?;
        validate_admin_conn(&mut conn, admin_id).await?;
        let groups = group::table
            .or_filter(group::name.ilike(&format!("%{}%", params)))
            .or_filter(group::description.ilike(&format!("%{}%", params)))
            .left_join(
                group_user::table.on(group_user::group_id
                    .eq(group::id)
                    .and(group_user::user_id.eq(exclude_user_id))),
            )
            .filter(group_user::group_id.is_null())
            .limit(20)
            .select(Group::as_select())
            .load::<Group>(&mut conn)
            .await?;
        Ok(groups)
    }

    pub async fn add_groups(&self, user_id: &Id, group_ids: &[Id], admin_id: &Id) -> DbResult<()> {
        let mut conn = self.pg_pool.get().await?;
        validate_admin_conn(&mut conn, admin_id).await?;
        let rows = group_ids
            .iter()
            .map(|gid| {
                (
                    group_user::user_id.eq(user_id),
                    group_user::group_id.eq(gid),
                )
            })
            .collect::<Vec<_>>();
        diesel::insert_into(group_user::table)
            .values(rows)
            .execute(&mut conn)
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    pub async fn read_groups(&self, user_id: &Id, admin_id: &Id) -> DbResultMultiple<Group> {
        let mut conn = self.pg_pool.get().await?;
        validate_admin_conn(&mut conn, admin_id).await?;
        let groups = group_user::table
            .filter(group_user::user_id.eq(user_id))
            .inner_join(group::table)
            .select(Group::as_select())
            .load::<Group>(&mut conn)
            .await?;
        Ok(groups)
    }

    pub async fn read_many_auth(
        &self,
        params: &SelectManyUsers,
        user_id: &Id,
    ) -> DbResultMultiple<User> {
        let mut conn = self.pg_pool.get().await?;
        validate_admin_conn(&mut conn, user_id).await?;
        let query = build_select_many_query(params);
        let users = query.order_by(user::id).load::<User>(&mut conn).await?;
        Ok(users)
    }
}

impl DbReadOne<Id, UserDisplay> for PgUserRepository {
    async fn read_one(&self, params: &Id) -> DbResultSingle<UserDisplay> {
        let mut conn = self.pg_pool.get().await?;
        let u = user::table.find(&params).first::<User>(&mut conn).await?;
        validate_user(&u)?;
        let u = UserDisplay {
            has_groups: UserBackend::has_groups(&mut conn, &u.id).await?,
            user: u,
        };
        Ok(u)
    }

    async fn read_one_auth(&self, params: &Id, user_id: &Id) -> DbResultSinglePerm<UserDisplay> {
        let mut conn = self.pg_pool.get().await?;
        validate_admin_conn(&mut conn, user_id).await?;
        let u = user::table.find(&params).first::<User>(&mut conn).await?;
        let u = UserDisplay {
            has_groups: UserBackend::has_groups(&mut conn, &u.id).await?,
            user: u,
        };
        Ok(DbDataPerm::new(
            u,
            (true, vec![GroupProbePermission::full()]),
        ))
    }
}

impl DbCreate<UserCreate, User> for PgUserRepository {
    async fn create(&self, data: &UserCreate) -> DbResultSingle<User> {
        let mut conn = self.pg_pool.get().await?;
        UserBackend::insert(&mut conn, data).await
    }

    async fn create_auth(&self, data: &UserCreate, user_id: &Id) -> DbResultSingle<User> {
        let mut conn = self.pg_pool.get().await?;
        validate_admin_conn(&mut conn, user_id).await?;
        UserBackend::insert(&mut conn, data).await
    }
}

impl DbUpdate<UserUpdate, UserDisplay> for PgUserRepository {
    async fn update(&self, params: &UserUpdate) -> DbResultMultiple<UserDisplay> {
        let mut conn = self.pg_pool.get().await?;
        let u = user::table
            .find(&params.id)
            .first::<User>(&mut conn)
            .await?;
        validate_user(&u)?;
        let has_groups = UserBackend::has_groups(&mut conn, &u.id).await?;
        UserBackend::update(&mut conn, params, has_groups).await
    }

    async fn update_auth(
        &self,
        params: &UserUpdate,
        user_id: &Id,
    ) -> DbResultMultiple<UserDisplay> {
        let mut conn = self.pg_pool.get().await?;
        validate_admin_conn(&mut conn, user_id).await?;
        UserBackend::update(&mut conn, params, true).await
    }
}

impl DbDelete<Id, User> for PgUserRepository {
    async fn delete(&self, params: &Id) -> DbResultMultiple<User> {
        let mut conn = self.pg_pool.get().await?;
        self.read_one(params).await?;
        diesel::delete(user::table.find(params))
            .get_results(&mut conn)
            .await
            .map_err(DbError::from)
    }

    async fn delete_auth(&self, params: &Id, user_id: &Id) -> DbResultMultiple<User> {
        let mut conn = self.pg_pool.get().await?;
        validate_admin_conn(&mut conn, user_id).await?;
        diesel::delete(user::table.find(params))
            .get_results(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

struct UserBackend {}

impl UserBackend {
    pub async fn has_groups(conn: &mut AsyncPgConnection, user_id: &Id) -> DbResult<bool> {
        let group = group_user::table
            .filter(group_user::user_id.eq(user_id))
            .select(GroupUser::as_select())
            .first(conn)
            .await;
        group.map(|_| true).or(Ok(false))
    }

    async fn insert(conn: &mut AsyncPgConnection, data: &UserCreate) -> DbResultSingle<User> {
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
            .get_result(conn)
            .await
            .map_err(DbError::from)
    }

    async fn update(
        conn: &mut AsyncPgConnection,
        params: &UserUpdate,
        has_groups: bool,
    ) -> DbResultMultiple<UserDisplay> {
        let updated_users = diesel::update(user::table.find(&params.id))
            .set(params)
            .get_results(conn)
            .await?
            .into_iter()
            .map(|u| UserDisplay::from(u, has_groups))
            .collect::<Vec<_>>();
        Ok(updated_users)
    }
}

fn build_select_many_query<'a>(params: &'a SelectManyUsers) -> BoxedQuery<'a, Pg> {
    let mut query = user::table.into_boxed();

    if let Some(id) = &params.id {
        query = query.filter(user::id.eq(id));
    }

    if let Some(n) = &params.name {
        query = query.filter(user::name.ilike(format!("%{n}%")))
    }

    if let Some(s) = &params.surname {
        query = query.filter(user::surname.ilike(format!("%{s}%")))
    }

    if let Some(e) = &params.email {
        query = query.filter(user::email.ilike(format!("%{e}%")))
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
    query
}
