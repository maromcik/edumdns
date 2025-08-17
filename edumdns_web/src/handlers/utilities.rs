use crate::MIN_PASS_LEN;
use actix_web::HttpRequest;


#[macro_export]
macro_rules! authorized {
    ($e:expr, $p:expr) => {{
        match $e {
            None => {
                let path = format!("/user/login?ret={}", $p);
                return Ok(HttpResponse::SeeOther()
                    .insert_header((LOCATION, path))
                    .finish());
            }
            Some(v) => v,
        }
    }};
}

pub fn validate_password(password: &str) -> bool {
    let (lower, upper, numeric, special) =
        password
            .chars()
            .fold((false, false, false, false), |(l, u, n, s), c| {
                (
                    {
                        if c.is_lowercase() {
                            true
                        } else {
                            l
                        }
                    },
                    {
                        if c.is_uppercase() {
                            true
                        } else {
                            u
                        }
                    },
                    {
                        if c.is_numeric() {
                            true
                        } else {
                            n
                        }
                    },
                    {
                        if !c.is_alphanumeric() {
                            true
                        } else {
                            s
                        }
                    },
                )
            });
    lower && upper && numeric && special && password.len() >= MIN_PASS_LEN
}

pub fn is_htmx(request: &HttpRequest) -> bool {
    request
        .headers()
        .get("HX-Request")
        .map_or(false, |v| v == "true")
}
