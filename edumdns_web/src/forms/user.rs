use edumdns_db::repositories::common::Id;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
pub struct UserCreateForm {
    pub email: String,
    pub password: String,
    pub confirm_password: String,
    pub name: String,
    pub surname: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct UserUpdateForm {
    pub email: String,
    pub name: String,
    pub surname: String,
}
#[derive(Debug, Clone, Deserialize)]
pub struct UserUpdatePasswordForm {
    pub old_password: String,
    pub new_password: String,
    pub confirm_password: String,
}

#[derive(Deserialize)]
pub struct UserLoginReturnURL {
    pub ret: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserLoginForm {
    pub email: String,
    pub password: String,
    pub return_url: String,
}

pub trait EmailForm {
    type FormField<'a>
    where
        Self: 'a;
    fn name(&self) -> Self::FormField<'_>;
    fn from(&self) -> Self::FormField<'_>;
    fn tel(&self) -> Self::FormField<'_>;
    fn country(&self) -> Self::FormField<'_>;
    fn city(&self) -> Self::FormField<'_>;
    fn address(&self) -> Self::FormField<'_>;
    fn message(&self) -> Self::FormField<'_>;

    fn bike_id(&self) -> Option<Id>;
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContactAdminBikeForm {
    pub bike_id: Id,
    pub name: String,
    pub from: String,
    pub tel: String,
    pub country: String,
    pub city: String,
    pub address: String,
    pub message: String,
}

impl EmailForm for ContactAdminBikeForm {
    type FormField<'a> = &'a str;

    fn name(&self) -> Self::FormField<'_> {
        self.name.as_str()
    }

    fn from(&self) -> Self::FormField<'_> {
        self.from.as_str()
    }

    fn tel(&self) -> Self::FormField<'_> {
        self.tel.as_str()
    }
    fn country(&self) -> Self::FormField<'_> {
        self.country.as_str()
    }

    fn city(&self) -> Self::FormField<'_> {
        self.city.as_str()
    }

    fn address(&self) -> Self::FormField<'_> {
        self.address.as_str()
    }

    fn message(&self) -> Self::FormField<'_> {
        self.message.as_str()
    }

    fn bike_id(&self) -> Option<Id> {
        Some(self.bike_id)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContactAdminGeneralForm {
    pub name: String,
    pub from: String,
    pub tel: String,
    pub country: String,
    pub city: String,
    pub address: String,
    pub message: String,
}

impl EmailForm for ContactAdminGeneralForm {
    type FormField<'a> = &'a str;

    fn name(&self) -> Self::FormField<'_> {
        self.name.as_str()
    }

    fn from(&self) -> Self::FormField<'_> {
        self.from.as_str()
    }

    fn tel(&self) -> Self::FormField<'_> {
        self.tel.as_str()
    }
    fn country(&self) -> Self::FormField<'_> {
        self.country.as_str()
    }

    fn city(&self) -> Self::FormField<'_> {
        self.city.as_str()
    }

    fn address(&self) -> Self::FormField<'_> {
        self.address.as_str()
    }
    fn message(&self) -> Self::FormField<'_> {
        self.message.as_str()
    }

    fn bike_id(&self) -> Option<Id> {
        None
    }
}
