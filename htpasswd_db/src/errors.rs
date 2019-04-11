use std::error;
use std::fmt;

/// Authentication failure.
#[derive(Debug)]
pub enum AuthError {
    /// Returned if the credentials are incorrect or can not be
    /// validated against the on-disk credentials.
    NotAuthenticated(BadCredentials),

    /// Indicates a faulty password hash value or failure to hash the
    /// provided credentials.
    StorageError(bcrypt::BcryptError),
}

impl PartialEq for AuthError {
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

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Authentication failed.")
    }
}

impl error::Error for AuthError {
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
        impl From<$f> for AuthError {
            fn from(f: $f) -> Self {
                $e(f)
            }
        }
    };
}

impl_from_error!(bcrypt::BcryptError, AuthError::StorageError);
impl_from_error!(BadCredentials, AuthError::NotAuthenticated);

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
pub enum BadCredentials {
    /// User does not exist.
    NoSuchUser,

    /// User exists but their password is incorrect.
    InvalidPassword,

    /// User exists but their password is stored in an insecure way,
    /// and won't be validated.
    InsecureStorage,
}

impl fmt::Display for BadCredentials {
    /// Display on `BadCredentials` hides all information about the concrete
    /// problem that led to credentials being invalid.
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Authentication failed.")
    }
}

impl<'a> error::Error for BadCredentials {}
