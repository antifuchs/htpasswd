use nom::types::CompleteStr;
use nom::*;
use std::collections::hash_map::HashMap;

/// An error kind returned from the parser.
#[derive(Debug)]
pub enum Error<'a> {
    /// Returned when nom fails to parse a .htaccess file.
    ParseError { error: Err<&'a str> },

    /// Returned if nom didn't consume the entire .htaccess file.
    GarbageAtEnd(&'a str),
}

impl<'a> From<Err<&'a str>> for Error<'a> {
    fn from(error: Err<&'a str>) -> Self {
        Error::ParseError { error }
    }
}

/// Represents a password hashed with a particular method.
#[derive(Debug, PartialEq)]
pub enum PasswordHash<'a> {
    Bcrypt(&'a str),
    SHA1(&'a str),
    MD5(&'a str),
    Crypt(&'a str),
}

named!(bcrypt_pw<&str, PasswordHash>,
       do_parse!(peek!(alt_complete!(tag!("$2a$") | tag!("$2y$") | tag!("$2b$"))) >>
                 pw: not_line_ending >>
                 (PasswordHash::Bcrypt(pw))
       )
);

named!(sha1_pw<&str, PasswordHash>,
       do_parse!(tag!("{SHA}") >>
                 pw: not_line_ending >>
                 (PasswordHash::SHA1(pw)))
);

named!(md5_pw<&str, PasswordHash>,
       do_parse!(tag!("$apr1$") >>
                 pw: not_line_ending >>
                 (PasswordHash::MD5(pw)))
);

named!(crypt_pw<&str, PasswordHash>,
       do_parse!(pw: not_line_ending >>
                 (PasswordHash::Crypt(pw)))
);

named!(
    password<&str, PasswordHash>,
    alt_complete!(bcrypt_pw | sha1_pw | md5_pw | crypt_pw)
);

#[derive(Debug, PartialEq)]
pub struct Entry<'a> {
    user: &'a str,
    pw_hash: PasswordHash<'a>,
}

named!(
    entry<&str, (&str, PasswordHash)>,
    do_parse!(user: terminated!(is_not!(":"), tag!(":")) >>
              pw_hash: password >>
              ((user, pw_hash)))
);

named!(entries<&str, HashMap<&str, PasswordHash>>,
       do_parse!(entries: complete!(terminated!(separated_list!(tag!("\n"), entry), opt!(line_ending))) >>
                 (entries.into_iter().collect()))
);

/// Parses an htpasswd-formatted string and returns the entries in it
/// as a hash table, mapping user names to password hashes.
pub fn parse_htpasswd_str(contents: &str) -> Result<HashMap<&str, PasswordHash<'_>>, Error> {
    let (rest, entries) = entries(contents)?;
    if !rest.is_empty() {
        return Err(Error::GarbageAtEnd(rest));
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_tag() {
        assert_eq!(
            ("", PasswordHash::Bcrypt("$2y$foobar")),
            password("$2y$foobar").unwrap()
        );
        assert_eq!(
            ("\n", PasswordHash::Bcrypt("$2y$foobar")),
            password("$2y$foobar\n").unwrap()
        );
        assert_eq!(
            ("\r\n", PasswordHash::Bcrypt("$2y$foobar")),
            password("$2y$foobar\r\n").unwrap()
        );
        assert_eq!(
            ("\n", PasswordHash::SHA1("foobar")),
            password("{SHA}foobar\n").unwrap()
        );
        assert_eq!(
            ("\n", PasswordHash::MD5("foobar")),
            password("$apr1$foobar\n").unwrap()
        );
        assert_eq!(
            ("\n", PasswordHash::Crypt("foobar")),
            password("foobar\n").unwrap()
        );
    }

    #[test]
    fn whole_line() {
        assert_eq!(
            ("\n", ("asf", PasswordHash::Bcrypt("$2y$foobar"))),
            entry("asf:$2y$foobar\n").unwrap()
        )
    }

    #[test]
    fn htpasswd_str() {
        let entries = parse_htpasswd_str(
            "asf:$2y$05$6mQlzTSUkBbyHDU7XIwQaO3wOEDZpUdYR4YxRXgM2gqe/nwJSy.96
bsf:$2y$05$9U5xoWYrBX687.C.MEhsae5LfOrlUqqMSfE2Cpo4K.jyvy3lA.Ijy",
        )
        .unwrap();
        assert_eq!(
            Some(&PasswordHash::Bcrypt(
                "$2y$05$6mQlzTSUkBbyHDU7XIwQaO3wOEDZpUdYR4YxRXgM2gqe/nwJSy.96"
            )),
            entries.get("asf")
        );
        assert_eq!(
            Some(&PasswordHash::Bcrypt(
                "$2y$05$9U5xoWYrBX687.C.MEhsae5LfOrlUqqMSfE2Cpo4K.jyvy3lA.Ijy"
            )),
            entries.get("bsf")
        );
    }
}
