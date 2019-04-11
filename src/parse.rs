use super::{Input, PasswordHash};
use nom::types::CompleteStr;
use nom::*;
use nom_locate::LocatedSpan;
use std::collections::hash_map::HashMap;
use std::fmt;

/// A list of things that can go wrong in parsing.
#[derive(Debug, PartialEq, Clone)]
pub enum ParseErrorKind {
    /// Indicates that the first field ("username") failed to parse.
    BadUsername,

    /// Indicates that the ":" separator was not detected on a line.
    BadPassword,

    /// Indicates that entries at the end were missing.
    GarbageAtEnd,

    BrokenHtpasswd,

    /// An unexpected parse error, indicates a bug in the htpasswd crate
    Unknown,
}

impl From<u32> for ParseErrorKind {
    fn from(_: u32) -> Self {
        ParseErrorKind::Unknown
    }
}

impl fmt::Display for ParseErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        use ParseErrorKind::*;
        write!(
            f,
            "{}",
            match self {
                BadUsername => "badly-formatted user name field (forgot a `:`?)",
                BadPassword => "badly-formatted password field",
                GarbageAtEnd => "last line in file is not recognized",
                BrokenHtpasswd => ".htpasswd didn't parse",
                Unknown => "bug in htpasswd crate",
            }
        )
    }
}

type Span<'a> = LocatedSpan<Input<'a>>;

/// Indicates nom failed to parse a .htaccess file.
type ParseError<'a> = Err<Span<'a>, ParseErrorKind>;

#[derive(PartialEq, Debug)]
struct UserToken(String);

named!(bcrypt_pw<Span, PasswordHash>,
       do_parse!(peek!(alt_complete!(tag!("$2a$") | tag!("$2y$") | tag!("$2b$"))) >>
                 pw: not_line_ending >>
                 (PasswordHash::Bcrypt(pw.to_string()))
       )
);

named!(sha1_pw<Span, PasswordHash>,
       do_parse!(tag!("{SHA}") >>
                 pw: not_line_ending >>
                 (PasswordHash::SHA1(pw.to_string())))
);

named!(md5_pw<Span, PasswordHash>,
       do_parse!(tag!("$apr1$") >>
                 pw: not_line_ending >>
                 (PasswordHash::MD5(pw.to_string()))));

named!(crypt_pw<Span, PasswordHash>,
       do_parse!(pw: not_line_ending >>
                 (PasswordHash::Crypt(pw.to_string())))
);

named!(password<Span, PasswordHash, ParseErrorKind>,
       return_error!(ErrorKind::Custom(ParseErrorKind::BadPassword),
                     fix_error!(ParseErrorKind,
                               alt!(bcrypt_pw | sha1_pw | md5_pw | crypt_pw))));

named!(user<Span, UserToken, ParseErrorKind>,
       return_error!(ErrorKind::Custom(ParseErrorKind::BadUsername),
                     fix_error!(ParseErrorKind,
                                do_parse!(user: terminated!(is_not!(":"), tag!(":")) >>
                                          (UserToken(user.fragment.to_string()))))));

named!(
    entry<Span, (UserToken, PasswordHash), ParseErrorKind>,
    do_parse!(user: user >>
              pw_hash: password >>
              ((user, pw_hash)))
);

named!(entries<Span, Vec<(UserToken, PasswordHash)>, ParseErrorKind>,
       do_parse!(entries: terminated!(separated_list!(fix_error!(ParseErrorKind, tag!("\n")),
                                                      entry),
                                      fix_error!(ParseErrorKind, opt!(line_ending))) >>
                 return_error!(ErrorKind::Custom(ParseErrorKind::GarbageAtEnd),
                               fix_error!(ParseErrorKind, eof!())) >>
                 (entries))
);

#[derive(Debug, PartialEq)]
pub struct ParseFailure {
    kind: ParseErrorKind,
    offset: usize,
    line: u32,
    column: usize,
}

impl Default for ParseFailure {
    fn default() -> Self {
        ParseFailure {
            kind: ParseErrorKind::Unknown,
            offset: 0,
            line: 0,
            column: 0,
        }
    }
}

impl<'a> From<ParseError<'a>> for ParseFailure {
    fn from(e: ParseError<'a>) -> Self {
        if let Err::Failure(c) | Err::Error(c) = e {
            let Context::Code(input, err_kind) = c;
            if let ErrorKind::Custom(kind) = err_kind {
                return ParseFailure {
                    kind,
                    offset: input.offset,
                    line: input.line,
                    column: input.get_column(),
                };
            }
        }
        // otherwise we have found a bug:
        ParseFailure::default()
    }
}

pub(crate) fn parse_entries(input: &str) -> Result<HashMap<String, PasswordHash>, ParseFailure> {
    let input = Span::new(CompleteStr::from(input));
    match entries(input) {
        Ok((_rest, entries)) => Ok(entries.into_iter().map(|(ut, pwt)| (ut.0, pwt)).collect()),

        Result::Err(e) => Result::Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _in<'a>(input: &'a str) -> Span<'a> {
        Span::new(CompleteStr::from(input))
    }

    #[test]
    fn password_tag() {
        assert_eq!(
            PasswordHash::Bcrypt("$2y$foobar".into()),
            password(_in("$2y$foobar")).unwrap().1
        );
        assert_eq!(
            PasswordHash::Bcrypt("$2y$foobar".into()),
            password(_in("$2y$foobar\n")).unwrap().1
        );
        assert_eq!(
            PasswordHash::Bcrypt("$2y$foobar".into()),
            password(_in("$2y$foobar\r\n")).unwrap().1
        );
        assert_eq!(
            PasswordHash::SHA1("foobar".into()),
            password(_in("{SHA}foobar\n")).unwrap().1
        );
        assert_eq!(
            PasswordHash::MD5("foobar".into()),
            password(_in("$apr1$foobar\n")).unwrap().1
        );
        assert_eq!(
            PasswordHash::Crypt("foobar".into()),
            password(_in("foobar\n")).unwrap().1
        );
    }

    #[test]
    fn whole_line() {
        let entry = entry(_in("asf:$2y$foobar\n")).unwrap().1;
        assert_eq!(
            (
                UserToken("asf".to_string()),
                PasswordHash::Bcrypt("$2y$foobar".into())
            ),
            (entry.0, entry.1)
        )
    }
}
