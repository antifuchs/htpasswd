use super::{Input, PasswordHash};
use nom::types::CompleteStr;
use nom::*;
use nom_locate::{position, LocatedSpan};
use std::collections::hash_map::HashMap;

/// A list of things that can go wrong in parsing.
#[derive(Debug, PartialEq)]
pub enum ParseErrorKind {
    /// Indicates that the first field ("username") failed to parse.
    BadUsername,

    /// Indicates that the ":" separator was not detected on a line.
    BadPassword,

    /// Indicates that entries at the end were missing.
    GarbageAtEnd,

    Bcrypt,
    SHA1,
    MD5,
    Crypt,

    BrokenHtpasswd,

    /// An unexpected parse error, indicates a bug in the htpasswd crate
    Unknown,
}

impl From<u32> for ParseErrorKind {
    fn from(f: u32) -> Self {
        ParseErrorKind::Unknown
    }
}

type Span<'a> = LocatedSpan<Input<'a>>;

/// Indicates nom failed to parse a .htaccess file.
pub type ParseError<'a> = nom::Err<Span<'a>, ParseErrorKind>;

struct PWToken<'a> {
    position: Span<'a>,
    hash: PasswordHash,
}

struct UserToken<'a> {
    position: Span<'a>,
    username: String,
}

named!(bcrypt_pw<Span, PWToken, ParseErrorKind>,
       return_error!(ErrorKind::Custom(ParseErrorKind::Bcrypt),
                     do_parse!(position: position!() >>
                               peek!(alt_complete!(tag!("$2a$") | tag!("$2y$") | tag!("$2b$"))) >>
                               pw: not_line_ending >>
                               (PWToken{position, hash: PasswordHash::Bcrypt(pw.to_string()),})
                     ))
);

named!(sha1_pw<Span, PWToken, ParseErrorKind>,
       return_error!(ErrorKind::Custom(ParseErrorKind::SHA1),
                     do_parse!(position: position!() >>
                               tag!("{SHA}") >>
                               pw: not_line_ending >>
                               (PWToken{position, hash: PasswordHash::SHA1(pw.to_string())})))
);

named!(md5_pw<Span, PWToken, ParseErrorKind>,
       return_error!(ErrorKind::Custom(ParseErrorKind::MD5),
                     do_parse!(position: position!() >>
                               tag!("$apr1$") >>
                               pw: not_line_ending >>
                               (PWToken{position, hash: PasswordHash::MD5(pw.to_string())})))
);

named!(crypt_pw<Span, PWToken, ParseErrorKind>,
       return_error!(ErrorKind::Custom(ParseErrorKind::Crypt),
                     do_parse!(position: position!() >>
                               pw: not_line_ending >>
                               (PWToken{position, hash: PasswordHash::Crypt(pw.to_string())})))
);

named!(password<Span, PWToken, ParseErrorKind>,
       return_error!(ErrorKind::Custom(ParseErrorKind::BadPassword),
                     alt!(bcrypt_pw | sha1_pw | md5_pw | crypt_pw)));

named!(user<Span, UserToken, ParseErrorKind>,
       return_error!(ErrorKind::Custom(ParseErrorKind::BadUsername),
                     do_parse!(position: position!() >>
                               user: terminated!(is_not!(":"), tag!(":")) >>
                               (UserToken{position, username: user.fragment.to_string()}))));

named!(
    entry<Span, (UserToken, PWToken), ParseErrorKind>,
    do_parse!(user: user >>
              pw_hash: password >>
              ((user, pw_hash)))
);

named!(entries<Span, Vec<(UserToken, PWToken)>, ParseErrorKind>,
       return_error!(ErrorKind::Custom(ParseErrorKind::BrokenHtpasswd),
                     do_parse!(entries: terminated!(separated_list!(tag!("\n"), entry), opt!(line_ending)) >>
                               add_return_error!(ErrorKind::Custom(ParseErrorKind::GarbageAtEnd), eof!()) >>
                               (entries)))
);

pub(crate) fn parse_entries(input: &str) -> Result<HashMap<String, PasswordHash>, ParseError> {
    let input = Span::new(CompleteStr::from(input));
    let (_rest, entries) = entries(input)?;
    Ok(entries
        .into_iter()
        .map(|(ut, pwt)| (ut.username, pwt.hash))
        .collect())
}
/*
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
                ("asf".to_string(), PasswordHash::Bcrypt("$2y$foobar".into()))
            ),
            entry("asf:$2y$foobar\n".into()).unwrap()
        )
    }
}
*/
