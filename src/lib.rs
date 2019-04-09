use bcrypt;
use nom;
use std::collections::hash_map::HashMap;

// The type to use as input to parsers in this crate.
pub use nom::types::CompleteStr as Input;

mod parse;

/// An error kind returned from the parser.
#[derive(Debug)]
pub enum Error<'a> {
    /// Indicates nom failed to parse a .htaccess file.
    ParseError(nom::Err<Input<'a>>),

    /// Indicates that a password storage scheme other than bcrypt was
    /// used.
    InsecureStorage,

    /// Indicates that the provided password does not match the one in
    /// password storage.
    IncorrectPassword,

    /// Returned if a user tried to authenticate that doesn't exist in
    /// the `PasswordDB`.
    InvalidUser(&'a str),

    /// Indicates a faulty password hash value.
    StorageError(bcrypt::BcryptError),
}

impl<'a> PartialEq for Error<'a> {
    fn eq(&self, other: &Self) -> bool {
        use Error::*;
        match (self, other) {
            (InsecureStorage, InsecureStorage) => true,
            (IncorrectPassword, IncorrectPassword) => true,
            (InvalidUser(l), InvalidUser(r)) => l == r,
            (ParseError(l), ParseError(r)) => l == r,

            // Hack: they don't derive PartialEq, so we assume all
            // storage errors are the same.
            (StorageError(_), StorageError(_)) => true,

            (_, _) => false,
        }
    }
}

macro_rules! impl_from_error {
    ($f: ty, $e: expr) => {
        impl<'a> From<$f> for Error<'a> {
            fn from(f: $f) -> Self {
                $e(f)
            }
        }
    };
}

impl_from_error!(nom::Err<Input<'a>>, Error::ParseError);
impl_from_error!(bcrypt::BcryptError, Error::StorageError);

/// Represents a password hashed with a particular method.
#[derive(Debug, PartialEq)]
enum PasswordHash<'a> {
    Bcrypt(&'a str),
    SHA1(&'a str),
    MD5(&'a str),
    Crypt(&'a str),
}

/// An in-memory representation of a `.htpasswd` file.
pub struct PasswordDB<'a>(HashMap<&'a str, PasswordHash<'a>>);

impl<'a> PasswordDB<'a> {
    /// Checks the provided username and password against the database
    /// and returns `Ok(())` if both match. Password mismatches result
    /// in `Error::IncorrectPassword` and missing users result in
    /// `Error::InvalidUser`.
    ///
    /// Returns `Errors::InsecureStorage` if the user's password hash is
    /// represented as anything other than bcrypt.
    pub fn validate(&self, user: &'a str, password: &str) -> Result<(), Error<'a>> {
        use crate::PasswordHash::*;
        match self.0.get(user).ok_or_else(|| Error::InvalidUser(user))? {
            Bcrypt(hash) => match bcrypt::verify(password, hash)? {
                true => Ok(()),
                false => Err(Error::IncorrectPassword),
            },
            _ => Err(Error::InsecureStorage),
        }
    }
}

/// Parses an htpasswd-formatted string and returns the entries in it
/// as a hash table, mapping user names to password hashes.
pub fn parse_htpasswd_str<'a>(contents: &'a str) -> Result<PasswordDB<'a>, Error> {
    let (_rest, entries) = parse::entries(contents.into())?;
    Ok(PasswordDB(entries))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_at_end() {
        assert!(parse_htpasswd_str(
            "asf:$2y$05$6mQlzTSUkBbyHDU7XIwQaO3wOEDZpUdYR4YxRXgM2gqe/nwJSy.96
___"
        )
        .is_err());
    }

    #[test]
    fn validate() {
        let entries = parse_htpasswd_str(
            "asf:$2y$05$6mQlzTSUkBbyHDU7XIwQaO3wOEDZpUdYR4YxRXgM2gqe/nwJSy.96
bsf:$2y$05$9U5xoWYrBX687.C.MEhsae5LfOrlUqqMSfE2Cpo4K.jyvy3lA.Ijy",
        )
        .unwrap();
        assert_eq!(Ok(()), entries.validate("asf", "oink"));
        assert_eq!(Ok(()), entries.validate("bsf", "areisntoiarnstoanrsit"));
        assert_eq!(
            Err(Error::IncorrectPassword),
            entries.validate("asf", "wrong")
        );
        assert_eq!(
            Err(Error::InvalidUser("unperson")),
            entries.validate("unperson", "unpassword")
        );
    }
}
