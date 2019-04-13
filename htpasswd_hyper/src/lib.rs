use htpasswd_db::PasswordDBSource;
use hyper::StatusCode;
use hyper::{service::Service, Request};
use hyper::{Body, Response};
use std::ops::Deref;

use futures::future::FutureResult;
use headers::{authorization::Basic, Authorization, HeaderMapExt};
use htpasswd_db::{AuthError, BadCredentials, PasswordDB};

/// Authenticates a request to the server using the HTTP Basic
/// Authorization protocol against a password DB loaded from a
/// .htpasswd.
pub fn basic_auth_via_htpasswd<T>(req: &Request<T>, db: &PasswordDB) -> Result<(), AuthError> {
    match req.headers().typed_get::<Authorization<Basic>>() {
        None => Err(AuthError::NotAuthenticated(BadCredentials::InvalidPassword)),
        Some(auth) => db.validate(auth.0.username(), auth.0.password()),
    }
}

pub struct Authenticate<T, S>
where
    S: PasswordDBSource,
    T: Service,
    T::Future: Into<FutureResult<Response<Body>, hyper::Error>>,
{
    upstream: T,
    source: S,
}

impl<T, S> Authenticate<T, S>
where
    S: PasswordDBSource,
    T: Service,
    T::Future: Into<FutureResult<Response<Body>, hyper::Error>>,
{
    pub fn new(upstream: T, source: S) -> Self {
        Authenticate { upstream, source }
    }
}

impl<T, S> Service for Authenticate<T, S>
where
    S: PasswordDBSource,
    T: Service,
    T::Future: Into<FutureResult<Response<Body>, hyper::Error>>,
{
    type ReqBody = T::ReqBody;
    type ResBody = Body;
    type Error = hyper::Error;
    type Future = FutureResult<Response<Body>, hyper::Error>;

    fn call(&mut self, request: Request<Self::ReqBody>) -> Self::Future {
        match self.source.get().deref() {
            Ok(db) => {
                if !basic_auth_via_htpasswd(&request, &db).is_ok() {
                    return futures::future::ok(
                        Response::builder()
                            .status(StatusCode::UNAUTHORIZED)
                            .body(Body::from("Unauthorized."))
                            .expect("Response should build"),
                    );
                } else {
                    self.upstream.call(request).into()
                }
            }
            Err(e) => {
                return futures::future::ok(
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from(e.to_string()))
                        .expect("Error"),
                );
            }
        }
    }
}
