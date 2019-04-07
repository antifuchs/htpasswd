use nom::*;
use std::collections::hash_map::HashMap;

/// Represents a password hashed with a particular method.
#[derive(Debug, PartialEq)]
pub enum PasswordHash<'a> {
    Bcrypt(&'a str),
    SHA1(&'a str),
    MD5(&'a str),
    Crypt(&'a str),
}

named!(
    password<&str, PasswordHash>,
    alt!(
        // TODO: I would like to recognize $2a$ and $2b$ here also.
        terminated!(recognize!(preceded!(tag!("$2y$"),
            take_until_s!("\n"))), tag!("\n")) => {|pw| PasswordHash::Bcrypt(pw)} |
        preceded!(tag!("{SHA}"), terminated!(take_until_s!("\n"), tag!("\n"))) => {|pw| PasswordHash::SHA1(pw)} |
        preceded!(tag!("$apr1$"), terminated!(take_until_s!("\n"), tag!("\n"))) => {|pw| PasswordHash::MD5(pw)} |
        terminated!(take_until_s!("\n"), tag!("\n")) => {|pw| PasswordHash::Crypt(pw)})
);

#[derive(Debug, PartialEq)]
pub struct Entry<'a> {
    user: &'a str,
    pw_hash: PasswordHash<'a>,
}

named!(
    entry<&str, (&str, PasswordHash)>,
    do_parse!(user: terminated!(take_until_s!(":"), tag!(":")) >>
              pw_hash: password >>
              ((user, pw_hash)))
);

named!(entries<&str, Vec<(&str, PasswordHash)>>, many0!(entry));

/// Parses an htpasswd-formatted string and returns the entries in it
/// as a hash table, mapping user names to password hashes.
pub fn parse_htpasswd_str(
    contents: &str,
) -> Result<HashMap<&str, PasswordHash<'_>>, Err<&str, u32>> {
    let (_, entries) = do_parse!(
        contents,
        entries: complete!(many0!(entry)) >> eof!() >> (entries)
    )?;
    Ok(entries.into_iter().collect())
}

// TODO: error types pls.
// pub fn parse_htpasswd_file<P: AsRef<Path>>(path: P) ->

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_tag() {
        assert_eq!(
            ("", PasswordHash::Bcrypt("$2y$foobar")),
            password("$2y$foobar\n").unwrap()
        );
        assert_eq!(
            ("", PasswordHash::SHA1("foobar")),
            password("{SHA}foobar\n").unwrap()
        );
        assert_eq!(
            ("", PasswordHash::MD5("foobar")),
            password("$apr1$foobar\n").unwrap()
        );
        assert_eq!(
            ("", PasswordHash::Crypt("foobar")),
            password("foobar\n").unwrap()
        );
    }

    #[test]
    fn whole_line() {
        assert_eq!(
            ("", ("asf", PasswordHash::Bcrypt("$2y$foobar"))),
            entry("asf:$2y$foobar\n").unwrap()
        )
    }
}
