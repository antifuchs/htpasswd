use super::{Input, PasswordHash};
use nom::*;
use std::collections::hash_map::HashMap;

/// A list of things that can go wrong in parsing.
pub enum ErrorKind {
    /// Indicates that the first field ("username") was empty.
    MissingUserName,

    /// Indicates that the ":" separator was not detected on a line.
    MissingSeparator,

    /// Indicates that entries at the end were missing.
    GarbageAtEnd,

    /// Additional context about the line that had the error.
    Line(usize),
}

/// Indicates nom failed to parse a .htaccess file.
pub type ParseError<'a> = nom::Err<Input<'a>>;

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

named!(
    entry<Input, (String, PasswordHash)>,
    do_parse!(user: terminated!(is_not!(":"), tag!(":")) >>
              pw_hash: password >>
              ((user.to_string(), pw_hash)))
);

named!(pub(crate) entries<Input, HashMap<String, PasswordHash>>,
       do_parse!(entries: terminated!(separated_list!(tag!("\n"), entry), opt!(line_ending)) >>
                 eof!() >>
                 (entries.into_iter().collect()))
);

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
