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
//! # fn main() -> Result<(), htpasswd::ParseFailure> {
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
use std::fmt;
use std::fs::read_to_string;
use std::io;
use std::io::Read;
use std::path::Path;
use std::str;
use std::str::FromStr;

// The type to use as input to parsers in this crate.
pub use nom::types::CompleteStr as Input;

mod errors;
mod parse;

pub use errors::*;
pub use parse::{ParseErrorKind, ParseFailure};

/// Represents a password hashed with a particular method.
#[derive(Debug, PartialEq)]
enum PasswordHash {
    Bcrypt(String),
    SHA1(String),
    MD5(String),
    Crypt(String),
}

/// An in-memory representation of a `.htpasswd` file.
#[derive(Debug, PartialEq)]
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

impl FromStr for PasswordDB {
    type Err = ParseFailure;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_htpasswd_str(s)
    }
}

/// Parses an htpasswd-formatted string and returns the entries in it
/// as a hash table, mapping user names to password hashes.
pub fn parse_htpasswd_str(contents: &str) -> Result<PasswordDB, ParseFailure> {
    let entries = parse::parse_entries(contents)?;
    Ok(PasswordDB(entries))
}

#[derive(Debug)]
pub enum LoadFailure {
    Parse(ParseFailure),
    Io(io::Error),
}

impl From<io::Error> for LoadFailure {
    fn from(f: io::Error) -> Self {
        LoadFailure::Io(f)
    }
}

impl From<ParseFailure> for LoadFailure {
    fn from(f: ParseFailure) -> Self {
        LoadFailure::Parse(f)
    }
}

impl fmt::Display for LoadFailure {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        use LoadFailure::*;
        write!(
            f,
            "loading htpasswd data: {}",
            match self {
                Parse(pf) => format!("parse failure:{}:{}: {}", pf.line, pf.column, pf.kind),
                Io(io) => format!("reading: {}", io),
            }
        )
    }
}

/// Allows loading .htpasswd data from certain types, e.g. `io.Read`
/// and `Path` objects. Note that due to the way the parser is
/// implemented, the entire input stream has to be read before
/// parsing.
trait HtpasswdLoad {
    /// Reads self to the end and parses a .htpasswd database from it.
    fn load_htpasswd(&mut self) -> Result<PasswordDB, LoadFailure>;
}

impl<T> HtpasswdLoad for T
where
    T: Read + Sized,
{
    fn load_htpasswd(&mut self) -> Result<PasswordDB, LoadFailure> {
        let mut str = String::new();
        self.read_to_string(&mut str)?;
        Ok(parse_htpasswd_str(&str)?)
    }
}

impl HtpasswdLoad for Path {
    fn load_htpasswd(&mut self) -> Result<PasswordDB, LoadFailure> {
        let contents = read_to_string(self)?;
        Ok(parse_htpasswd_str(&contents)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_fields() {
        assert_eq!(
            Err(ParseFailure {
                kind: ParseErrorKind::BadPassword,
                offset: 69,
                line: 2,
                column: 5
            }),
            parse_htpasswd_str(
                "asf:$2y$05$6mQlzTSUkBbyHDU7XIwQaO3wOEDZpUdYR4YxRXgM2gqe/nwJSy.96
___:"
            )
        );
        assert_eq!(
            Err(ParseFailure {
                kind: ParseErrorKind::BadUsername,
                offset: 0,
                line: 1,
                column: 1
            }),
            parse_htpasswd_str("___")
        );
        assert_eq!(
            Err(ParseFailure {
                kind: ParseErrorKind::BadUsername,
                offset: 0,
                line: 1,
                column: 1
            }),
            parse_htpasswd_str("")
        );
        assert_eq!(
            Err(ParseFailure {
                kind: ParseErrorKind::BadUsername,
                offset: 0,
                line: 1,
                column: 1
            }),
            parse_htpasswd_str(":")
        );
        assert_eq!(
            Err(ParseFailure {
                kind: ParseErrorKind::BadUsername,
                offset: 0,
                line: 1,
                column: 1
            }),
            parse_htpasswd_str(":")
        );
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
