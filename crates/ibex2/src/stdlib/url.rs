//! `URL` / `URLSearchParams` — pure, ungated (LLP 0059.000 §3.4).
//!
//! Full WHATWG parsing including IDNA and percent-encoding, delegated to the
//! `url` crate rather than hand-written, because §3.4 is explicit that a
//! partial URL parser is a security bug and not a missing feature.

use url::Url;

use crate::boundary::HostError;

/// The parsed components a `URL` object exposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrl {
    pub href: String,
    pub origin: String,
    pub protocol: String,
    pub username: String,
    pub password: String,
    pub host: String,
    pub hostname: String,
    pub port: String,
    pub pathname: String,
    pub search: String,
    pub hash: String,
}

/// Parse, optionally against a base — `new URL(input)` and `new URL(input, base)`.
pub fn parse(input: &str, base: Option<&str>) -> Result<ParsedUrl, HostError> {
    let parsed = match base {
        Some(base) => {
            let base = Url::parse(base)
                .map_err(|e| HostError::Failed(format!("TypeError: invalid base URL: {e}")))?;
            base.join(input)
        }
        None => Url::parse(input),
    }
    .map_err(|e| HostError::Failed(format!("TypeError: invalid URL: {e}")))?;

    Ok(components(&parsed))
}

fn components(parsed: &Url) -> ParsedUrl {
    // The web's accessors are not the crate's: `protocol` keeps its colon,
    // `search` and `hash` keep their leading sigil and are empty (not "?"/"#")
    // when absent, and `port` is the empty string when the port is the scheme's
    // default. Normalizing here is what "Rust owns semantics" means for URL.
    let host = match (parsed.host_str(), parsed.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_string(),
        (None, _) => String::new(),
    };
    ParsedUrl {
        href: parsed.as_str().to_string(),
        origin: parsed.origin().ascii_serialization(),
        protocol: format!("{}:", parsed.scheme()),
        username: parsed.username().to_string(),
        password: parsed.password().unwrap_or("").to_string(),
        host,
        hostname: parsed.host_str().unwrap_or("").to_string(),
        port: parsed.port().map(|p| p.to_string()).unwrap_or_default(),
        pathname: parsed.path().to_string(),
        search: match parsed.query() {
            Some("") | None => String::new(),
            Some(query) => format!("?{query}"),
        },
        hash: match parsed.fragment() {
            Some("") | None => String::new(),
            Some(fragment) => format!("#{fragment}"),
        },
    }
}

/// `URLSearchParams`, ordered and allowing duplicate names as the spec requires.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchParams {
    pairs: Vec<(String, String)>,
}

impl SearchParams {
    /// Parse from a query string, with or without a leading `?`.
    pub fn parse(input: &str) -> Self {
        let trimmed = input.strip_prefix('?').unwrap_or(input);
        let pairs = form_urlencoded::parse(trimmed.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        Self { pairs }
    }

    pub fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        Self { pairs }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn get_all(&self, name: &str) -> Vec<&str> {
        self.pairs
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn has(&self, name: &str) -> bool {
        self.pairs.iter().any(|(k, _)| k == name)
    }

    pub fn append(&mut self, name: &str, value: &str) {
        self.pairs.push((name.to_string(), value.to_string()));
    }

    /// `set`: replace the first occurrence and drop the rest, keeping position.
    /// Appends when absent.
    pub fn set(&mut self, name: &str, value: &str) {
        let mut seen = false;
        self.pairs.retain(|(k, _)| {
            if k != name {
                return true;
            }
            if seen {
                return false;
            }
            seen = true;
            true
        });
        match self.pairs.iter_mut().find(|(k, _)| k == name) {
            Some(pair) => pair.1 = value.to_string(),
            None => self.append(name, value),
        }
    }

    pub fn delete(&mut self, name: &str) {
        self.pairs.retain(|(k, _)| k != name);
    }

    pub fn pairs(&self) -> &[(String, String)] {
        &self.pairs
    }

    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    pub fn to_query_string(&self) -> String {
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs(self.pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_url_into_web_shaped_components() {
        let u = parse("https://user:pw@example.com:8443/a/b?x=1&y=2#frag", None).unwrap();
        assert_eq!(u.protocol, "https:");
        assert_eq!(u.username, "user");
        assert_eq!(u.password, "pw");
        assert_eq!(u.hostname, "example.com");
        assert_eq!(u.port, "8443");
        assert_eq!(u.host, "example.com:8443");
        assert_eq!(u.pathname, "/a/b");
        assert_eq!(u.search, "?x=1&y=2");
        assert_eq!(u.hash, "#frag");
        assert_eq!(u.origin, "https://example.com:8443");
    }

    #[test]
    fn a_default_port_serializes_as_an_empty_port() {
        let u = parse("https://example.com/", None).unwrap();
        assert_eq!(u.port, "", "the scheme's default port is not exposed");
        assert_eq!(u.host, "example.com");
        assert_eq!(u.origin, "https://example.com");
    }

    #[test]
    fn absent_query_and_fragment_are_empty_not_bare_sigils() {
        let u = parse("https://example.com/path", None).unwrap();
        assert_eq!(u.search, "");
        assert_eq!(u.hash, "");
    }

    #[test]
    fn resolves_against_a_base() {
        let u = parse("../c", Some("https://example.com/a/b/")).unwrap();
        assert_eq!(u.href, "https://example.com/a/c");
    }

    #[test]
    fn rejects_a_relative_url_with_no_base() {
        assert!(parse("/just/a/path", None).is_err());
        assert!(parse("not a url", None).is_err());
    }

    /// The reason §3.4 insists on a real parser: IDNA and percent-encoding are
    /// where a hand-rolled one becomes a security bug.
    #[test]
    fn applies_idna_and_percent_encoding() {
        let u = parse("https://例え.テスト/ä", None).unwrap();
        assert_eq!(u.hostname, "xn--r8jz45g.xn--zckzah");
        assert_eq!(u.pathname, "/%C3%A4");
    }

    #[test]
    fn search_params_keep_order_and_duplicates() {
        let params = SearchParams::parse("?a=1&b=2&a=3");
        assert_eq!(params.get("a"), Some("1"));
        assert_eq!(params.get_all("a"), vec!["1", "3"]);
        assert_eq!(params.len(), 3);
        assert!(params.has("b"));
        assert!(!params.has("c"));
    }

    #[test]
    fn set_replaces_in_place_and_drops_later_duplicates() {
        let mut params = SearchParams::parse("a=1&b=2&a=3");
        params.set("a", "9");
        assert_eq!(params.get_all("a"), vec!["9"]);
        // Position is preserved: 'a' stays first, ahead of 'b'.
        assert_eq!(params.to_query_string(), "a=9&b=2");
    }

    #[test]
    fn set_appends_when_the_name_is_absent() {
        let mut params = SearchParams::parse("a=1");
        params.set("z", "26");
        assert_eq!(params.to_query_string(), "a=1&z=26");
    }

    #[test]
    fn delete_removes_every_occurrence() {
        let mut params = SearchParams::parse("a=1&b=2&a=3");
        params.delete("a");
        assert_eq!(params.to_query_string(), "b=2");
    }

    #[test]
    fn serialization_escapes_and_round_trips() {
        let mut params = SearchParams::default();
        params.append("q", "a b&c=d");
        let encoded = params.to_query_string();
        assert_eq!(encoded, "q=a+b%26c%3Dd");
        assert_eq!(SearchParams::parse(&encoded).get("q"), Some("a b&c=d"));
    }
}
