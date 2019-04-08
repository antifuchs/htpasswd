use nom::types::CompleteStr as Input;
use nom::*;
use std::collections::hash_map::HashMap;

/// An error kind returned from the parser.
#[derive(Debug, PartialEq)]
pub enum Error<'a> {
    /// Returned when nom fails to parse a .htaccess file.
    ParseError { error: Err<Input<'a>> },
}

impl<'a> From<Err<Input<'a>>> for Error<'a> {
    fn from(error: Err<Input<'a>>) -> Self {
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

named!(bcrypt_pw<Input, PasswordHash>,
       do_parse!(peek!(alt_complete!(tag!("$2a$") | tag!("$2y$") | tag!("$2b$"))) >>
                 pw: not_line_ending >>
                 (PasswordHash::Bcrypt(*pw))
       )
);

named!(sha1_pw<Input, PasswordHash>,
       do_parse!(tag!("{SHA}") >>
                 pw: not_line_ending >>
                 (PasswordHash::SHA1(*pw)))
);

named!(md5_pw<Input, PasswordHash>,
       do_parse!(tag!("$apr1$") >>
                 pw: not_line_ending >>
                 (PasswordHash::MD5(*pw)))
);

named!(crypt_pw<Input, PasswordHash>,
       do_parse!(pw: not_line_ending >>
                 (PasswordHash::Crypt(*pw)))
);

named!(
    password<Input, PasswordHash>,
    alt_complete!(bcrypt_pw | sha1_pw | md5_pw | crypt_pw)
);

#[derive(Debug, PartialEq)]
pub struct Entry<'a> {
    user: Input<'a>,
    pw_hash: PasswordHash<'a>,
}

named!(
    entry<Input, (&str, PasswordHash)>,
    do_parse!(user: terminated!(is_not!(":"), tag!(":")) >>
              pw_hash: password >>
              ((*user, pw_hash)))
);

named!(entries<Input, HashMap<&str, PasswordHash>>,
       do_parse!(entries: terminated!(separated_list!(tag!("\n"), entry), opt!(line_ending)) >>
                 eof!() >>
                 (entries.into_iter().collect()))
);

/// Parses an htpasswd-formatted string and returns the entries in it
/// as a hash table, mapping user names to password hashes.
pub fn parse_htpasswd_str<'a>(
    contents: &'a str,
) -> Result<HashMap<&'a str, PasswordHash<'_>>, Error> {
    let (_rest, entries) = entries(contents.into())?;
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_tag() {
        assert_eq!(
            ("".into(), PasswordHash::Bcrypt("$2y$foobar".into())),
            password("$2y$foobar".into()).unwrap()
        );
        assert_eq!(
            ("\n".into(), PasswordHash::Bcrypt("$2y$foobar".into())),
            password("$2y$foobar\n".into()).unwrap()
        );
        assert_eq!(
            ("\r\n".into(), PasswordHash::Bcrypt("$2y$foobar".into())),
            password("$2y$foobar\r\n".into()).unwrap()
        );
        assert_eq!(
            (Input::from("\n"), PasswordHash::SHA1("foobar".into())),
            password("{SHA}foobar\n".into()).unwrap()
        );
        assert_eq!(
            (Input::from("\n"), PasswordHash::MD5("foobar".into())),
            password("$apr1$foobar\n".into()).unwrap()
        );
        assert_eq!(
            (Input::from("\n"), PasswordHash::Crypt("foobar".into())),
            password("foobar\n".into()).unwrap()
        );
    }

    #[test]
    fn whole_line() {
        assert_eq!(
            (
                "\n".into(),
                ("asf", PasswordHash::Bcrypt("$2y$foobar".into()))
            ),
            entry("asf:$2y$foobar\n".into()).unwrap()
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
                "$2y$05$6mQlzTSUkBbyHDU7XIwQaO3wOEDZpUdYR4YxRXgM2gqe/nwJSy.96".into()
            )),
            entries.get("asf")
        );
        assert_eq!(
            Some(&PasswordHash::Bcrypt(
                "$2y$05$9U5xoWYrBX687.C.MEhsae5LfOrlUqqMSfE2Cpo4K.jyvy3lA.Ijy".into()
            )),
            entries.get("bsf")
        );
    }

    #[test]
    fn garbage_at_end() {
        assert!(parse_htpasswd_str(
            "asf:$2y$05$6mQlzTSUkBbyHDU7XIwQaO3wOEDZpUdYR4YxRXgM2gqe/nwJSy.96
___"
        )
        .is_err());
    }
}
