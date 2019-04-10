//! # `htpasswd` - Load & validate credentials against Apache `.htpasswd` files.
//!
//! This crate provides types and functions that are useful for
//! validating credentials stored in
//! [`.htpasswd`](https://httpd.apache.org/docs/2.4/misc/password_encryptions.html)
//! files, as popularized by the Apache web server.
//!
//! ## Compatibility
//!
//! While `.htpasswd` files allow storing credentials in multiple
//! formats, this crate supports only the bcrypt password storage
//! format. Validating credentials against any other scheme (MD5,
//! SHA1, crypt or plaintext) will result in an authentication error
//! indicating that the storage format is insecure.
//!
//! # Example
//!
//! ```rust
//! # fn main() -> Result<(), htpasswd::ParseError<'static>> {
//! // the password is "secret"
//! let htpasswd_contents = "username:$2y$05$xT4MzeZJQmgv7XQQGYbf/eP.ING1L9m.iOZF/yUQIYKmYnmEYkfme";
//! let db = htpasswd::parse_htpasswd_str(htpasswd_contents)?;
//! assert_eq!(Ok(()), db.validate("username", "secret"));
//! # Ok(())
//! # }
//! ```
//!

use bcrypt;
use nom;
use std::collections::hash_map::HashMap;
use std::str;

// The type to use as input to parsers in this crate.
pub use nom::types::CompleteStr as Input;

mod errors;
mod parse;

pub use errors::*;
pub use parse::ParseError;

/// Represents a password hashed with a particular method.
#[derive(Debug, PartialEq)]
enum PasswordHash {
    Bcrypt(String),
    SHA1(String),
    MD5(String),
    Crypt(String),
}

/// An in-memory representation of a `.htpasswd` file.
pub struct PasswordDB(HashMap<String, PasswordHash>);

impl PasswordDB {
    /// Checks the provided username and password against the database
    /// and returns `Ok(())` if both match. Otherwise, returns an
    /// error indicating the problem with the provided or the stored
    /// credentials.
    pub fn validate<'a>(&self, user: &'a str, password: &str) -> Result<(), AuthError<'a>> {
        use crate::PasswordHash::*;
        match self
            .0
            .get(user)
            .ok_or_else(|| BadCredentials::NoSuchUser(user))?
        {
            Bcrypt(hash) => match bcrypt::verify(password, hash)? {
                true => Ok(()),
                false => Err(BadCredentials::InvalidPassword)?,
            },
            _ => Err(BadCredentials::InsecureStorage)?,
        }
    }
}

/// Parses an htpasswd-formatted string and returns the entries in it
/// as a hash table, mapping user names to password hashes.
pub fn parse_htpasswd_str<'a>(contents: &'a str) -> Result<PasswordDB, ParseError> {
    let entries = parse::parse_entries(contents)?;
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
            Err(AuthError::NotAuthenticated(BadCredentials::InvalidPassword)),
            entries.validate("asf", "wrong")
        );
        assert_eq!(
            Err(AuthError::NotAuthenticated(BadCredentials::NoSuchUser(
                "unperson"
            ))),
            entries.validate("unperson", "unpassword")
        );
    }
}
