use hyper::{Request};
use headers::{HeaderMapExt, Authorization, authorization::Basic};
use htpasswd_db::{PasswordDB, AuthError, BadCredentials};

/// Authenticates a request to the server using the HTTP Basic
/// Authorization protocol against a password DB loaded from a
/// .htpasswd.
pub fn basic_auth_via_htpasswd<T>(req: &Request<T>, db: &PasswordDB) -> Result<(), AuthError> {
    match req.headers().typed_get::<Authorization<Basic>>() {
        None => Err(AuthError::NotAuthenticated(BadCredentials::InvalidPassword)),
        Some(auth) => db.validate(auth.0.username(), auth.0.password())
    }
}
