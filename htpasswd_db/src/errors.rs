use std::error;
use std::fmt;

/// Authentication failure.
#[derive(Debug)]
pub enum AuthError<'a> {
    /// Returned if the credentials are incorrect or can not be
    /// validated against the on-disk credentials.
    NotAuthenticated(BadCredentials<'a>),

    /// Indicates a faulty password hash value or failure to hash the
    /// provided credentials.
    StorageError(bcrypt::BcryptError),
}

impl<'a> PartialEq for AuthError<'a> {
    fn eq(&self, other: &Self) -> bool {
        use AuthError::*;
        match (self, other) {
            (NotAuthenticated(l), NotAuthenticated(r)) => l == r,

            // Hack: they don't derive PartialEq, so we assume all
            // storage errors are the same.
            (StorageError(_), StorageError(_)) => true,

            (_, _) => false,
        }
    }
}

impl<'a> fmt::Display for AuthError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Authentication failed.")
    }
}

impl<'a> error::Error for AuthError<'a> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use AuthError::*;
        match self {
            StorageError(err) => Some(err),
            _ => None,
        }
    }
}

macro_rules! impl_from_error {
    ($f: ty, $e: expr) => {
        impl<'a> From<$f> for AuthError<'a> {
            fn from(f: $f) -> Self {
                $e(f)
            }
        }
    };
}

impl_from_error!(bcrypt::BcryptError, AuthError::StorageError);
impl_from_error!(BadCredentials<'a>, AuthError::NotAuthenticated);

/// All the things that could go wrong when checking credentials
/// against password storage.
///
/// # Security considerations
///
/// To safely use this enum in a production setting (where malicious
/// actors might try to gain information about the system and password
/// database), make sure to hide the concrete values of this enum. The
/// default `Display` trait implementation attempts to help here by
/// unconditionally rendering "Authentication failed.".
#[derive(Debug, PartialEq)]
pub enum BadCredentials<'a> {
    /// User does not exist.
    NoSuchUser(&'a str),

    /// User exists but their password is incorrect.
    InvalidPassword,

    /// User exists but their password is stored in an insecure way,
    /// and won't be validated.
    InsecureStorage,
}

impl<'a> fmt::Display for BadCredentials<'a> {
    /// Display on `BadCredentials` hides all information about the concrete
    /// problem that led to credentials being invalid.
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Authentication failed.")
    }
}

impl<'a> error::Error for BadCredentials<'a> {}
