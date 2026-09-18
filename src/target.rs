//! `[user@]host[:port]` parsing. IPv6 literals go in brackets: `[::1]:22`.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetError {
    #[error("target is empty")]
    Empty,
    #[error("target '{0}' starts with '-', which ssh would read as an option")]
    LeadingDash(String),
    #[error("target '{0}' has an invalid port (1-65535)")]
    BadPort(String),
    #[error("target '{0}' has an empty host")]
    EmptyHost(String),
    #[error("target '{0}' has an empty user before '@'")]
    EmptyUser(String),
}

pub fn parse(raw: &str) -> Result<Target, TargetError> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(TargetError::Empty);
    }
    if s.starts_with('-') {
        return Err(TargetError::LeadingDash(raw.to_string()));
    }
    let (user, rest) = match s.rsplit_once('@') {
        Some(("", _)) => return Err(TargetError::EmptyUser(raw.to_string())),
        Some((u, r)) => (Some(u.to_string()), r),
        None => (None, s),
    };
    let (host, port) = if let Some(inner) = rest.strip_prefix('[') {
        let (h, tail) = inner
            .split_once(']')
            .ok_or_else(|| TargetError::EmptyHost(raw.to_string()))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => Some(parse_port(p, raw)?),
            None if tail.is_empty() => None,
            None => return Err(TargetError::BadPort(raw.to_string())),
        };
        (h.to_string(), port)
    } else if rest.matches(':').count() == 1 {
        let (h, p) = rest.split_once(':').expect("exactly one colon");
        (h.to_string(), Some(parse_port(p, raw)?))
    } else {
        (rest.to_string(), None)
    };
    if host.is_empty() {
        return Err(TargetError::EmptyHost(raw.to_string()));
    }
    if host.starts_with('-') {
        return Err(TargetError::LeadingDash(raw.to_string()));
    }
    Ok(Target { user, host, port })
}

fn parse_port(p: &str, raw: &str) -> Result<u16, TargetError> {
    p.parse::<u16>()
        .ok()
        .filter(|n| *n != 0)
        .ok_or_else(|| TargetError::BadPort(raw.to_string()))
}

impl Target {
    /// Fill in user/port only where the target didn't specify them.
    pub fn with_defaults(mut self, user: Option<&str>, port: Option<u16>) -> Target {
        if self.user.is_none() {
            self.user = user.map(String::from);
        }
        if self.port.is_none() {
            self.port = port;
        }
        self
    }

    /// `-p PORT` / `-l USER` pieces for ssh. The host itself is passed separately after `--`.
    pub fn ssh_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(p) = self.port {
            args.push("-p".to_string());
            args.push(p.to_string());
        }
        if let Some(u) = &self.user {
            args.push("-l".to_string());
            args.push(u.clone());
        }
        args
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(u) = &self.user {
            write!(f, "{u}@")?;
        }
        if self.host.contains(':') {
            write!(f, "[{}]", self.host)?;
        } else {
            write!(f, "{}", self.host)?;
        }
        if let Some(p) = self.port {
            write!(f, ":{p}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(user: Option<&str>, host: &str, port: Option<u16>) -> Target {
        Target {
            user: user.map(String::from),
            host: host.to_string(),
            port,
        }
    }

    #[test]
    fn parses_every_shape() {
        assert_eq!(parse("host").unwrap(), t(None, "host", None));
        assert_eq!(
            parse("deploy@host").unwrap(),
            t(Some("deploy"), "host", None)
        );
        assert_eq!(parse("host:2222").unwrap(), t(None, "host", Some(2222)));
        assert_eq!(
            parse("deploy@10.0.0.5:2222").unwrap(),
            t(Some("deploy"), "10.0.0.5", Some(2222))
        );
        assert_eq!(parse("[::1]:22").unwrap(), t(None, "::1", Some(22)));
        assert_eq!(parse("[::1]").unwrap(), t(None, "::1", None));
        assert_eq!(parse("fe80::1").unwrap(), t(None, "fe80::1", None));
        assert_eq!(parse("  host  ").unwrap(), t(None, "host", None));
    }

    #[test]
    fn rejects_option_lookalikes() {
        assert_eq!(
            parse("-oProxyCommand=evil"),
            Err(TargetError::LeadingDash("-oProxyCommand=evil".into()))
        );
        assert_eq!(
            parse("user@-host"),
            Err(TargetError::LeadingDash("user@-host".into()))
        );
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(parse(""), Err(TargetError::Empty));
        assert_eq!(
            parse("host:abc"),
            Err(TargetError::BadPort("host:abc".into()))
        );
        assert_eq!(parse("host:0"), Err(TargetError::BadPort("host:0".into())));
        assert_eq!(
            parse("host:70000"),
            Err(TargetError::BadPort("host:70000".into()))
        );
        assert_eq!(parse("[::1]x"), Err(TargetError::BadPort("[::1]x".into())));
        assert_eq!(parse("@host"), Err(TargetError::EmptyUser("@host".into())));
        assert_eq!(parse("user@"), Err(TargetError::EmptyHost("user@".into())));
        assert_eq!(parse(":22"), Err(TargetError::EmptyHost(":22".into())));
    }

    #[test]
    fn defaults_fill_only_gaps() {
        let got = parse("host")
            .unwrap()
            .with_defaults(Some("deploy"), Some(2222));
        assert_eq!(got, t(Some("deploy"), "host", Some(2222)));
        let kept = parse("root@host:22")
            .unwrap()
            .with_defaults(Some("deploy"), Some(2222));
        assert_eq!(kept, t(Some("root"), "host", Some(22)));
    }

    #[test]
    fn ssh_args_and_display() {
        let full = t(Some("deploy"), "host", Some(2222));
        assert_eq!(full.ssh_args(), vec!["-p", "2222", "-l", "deploy"]);
        assert_eq!(full.to_string(), "deploy@host:2222");
        let bare = t(None, "host", None);
        assert!(bare.ssh_args().is_empty());
        assert_eq!(bare.to_string(), "host");
    }
}
