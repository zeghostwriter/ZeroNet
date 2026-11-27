//! Syntax colouring for a share link, so the wall of `vless://…?a=b&c=d#name`
//! reads as its parts rather than one grey run.
//!
//! The rule that matters: the coloured spans concatenate back to the exact
//! input, byte for byte. The share modal leans on that — a terminal
//! drag-select copies the glyphs, not our styling, so colour must never add,
//! drop or reorder a character. Every branch below pushes the source text
//! through unchanged and only chooses a colour for it.
//!
//! The scheme, the credential, the host, the port, each query key and value,
//! and the `#name` fragment each get their own colour from the active theme,
//! so the eye lands on the name and the host without reading the whole line.

use ratatui::style::{Modifier, Style};
use ratatui::text::Span;

use crate::theme::Theme;

/// Break a share link into coloured [`Span`]s. Concatenating their text
/// reproduces `uri` exactly; a string that does not look like a link comes
/// back as one plain span rather than being mangled.
pub fn highlight_link(uri: &str, theme: &Theme) -> Vec<Span<'static>> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut push = |text: &str, style: Style| {
        if !text.is_empty() {
            spans.push(Span::styled(text.to_string(), style));
        }
    };

    let sep = Style::default().fg(theme.muted);
    let scheme_style = Style::default()
        .fg(theme.accent_bright)
        .add_modifier(Modifier::BOLD);

    // Everything hangs off the `scheme://` marker; without it there is no link
    // structure to find, so the text is returned as-is.
    let Some(after_scheme_at) = uri.find("://") else {
        push(uri, Style::default().fg(theme.text));
        return spans;
    };
    let scheme_end = after_scheme_at + 3;
    push(&uri[..scheme_end], scheme_style);
    let rest = &uri[scheme_end..];

    // The fragment (the node's display name) is split off first: it is free
    // text and may itself contain '?', '&' or '#'.
    let (before_fragment, fragment) = match rest.split_once('#') {
        Some((body, frag)) => (body, Some(frag)),
        None => (rest, None),
    };

    // Then the query, so the authority is what is left in front of '?'.
    let (authority, query) = match before_fragment.split_once('?') {
        Some((auth, q)) => (auth, Some(q)),
        None => (before_fragment, None),
    };

    highlight_authority(authority, theme, &mut push, sep);

    if let Some(query) = query {
        push("?", sep);
        highlight_query(query, theme, &mut push, sep);
    }

    if let Some(fragment) = fragment {
        push("#", sep);
        push(
            fragment,
            Style::default().fg(theme.ok).add_modifier(Modifier::BOLD),
        );
    }

    spans
}

/// `credential@host:port` (any part may be absent). The credential is the
/// UUID or password; splitting on the last '@' keeps a host that has none.
fn highlight_authority(
    authority: &str,
    theme: &Theme,
    push: &mut impl FnMut(&str, Style),
    sep: Style,
) {
    let host_port = match authority.rsplit_once('@') {
        Some((credential, host_port)) => {
            push(credential, Style::default().fg(theme.warn));
            push("@", sep);
            host_port
        }
        None => authority,
    };
    highlight_host_port(host_port, theme, push, sep);
}

/// `host:port`, where the host may be a bracketed IPv6 literal that itself
/// contains colons, so the port is only the `:digits` after the `]`.
fn highlight_host_port(
    host_port: &str,
    theme: &Theme,
    push: &mut impl FnMut(&str, Style),
    sep: Style,
) {
    let host_style = Style::default().fg(theme.accent_bright);
    let port_style = Style::default().fg(theme.info);
    if let Some(close) = host_port
        .strip_prefix('[')
        .and_then(|_| host_port.find(']'))
    {
        // `[v6]` then optional `:port`.
        push(&host_port[..=close], host_style);
        let tail = &host_port[close + 1..];
        if let Some(port) = tail.strip_prefix(':') {
            push(":", sep);
            push(port, port_style);
        } else {
            push(tail, host_style);
        }
        return;
    }
    match host_port.rsplit_once(':') {
        Some((host, port)) => {
            push(host, host_style);
            push(":", sep);
            push(port, port_style);
        }
        None => push(host_port, host_style),
    }
}

/// `key=value&key=value`, keys and values in their own colours.
fn highlight_query(query: &str, theme: &Theme, push: &mut impl FnMut(&str, Style), sep: Style) {
    let key_style = Style::default().fg(theme.accent);
    let value_style = Style::default().fg(theme.text);
    for (index, pair) in query.split('&').enumerate() {
        if index > 0 {
            push("&", sep);
        }
        match pair.split_once('=') {
            Some((key, value)) => {
                push(key, key_style);
                push("=", sep);
                push(value, value_style);
            }
            None => push(pair, key_style),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::Theme;

    fn theme() -> Theme {
        Theme::default()
    }

    fn joined(uri: &str) -> String {
        highlight_link(uri, &theme())
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    /// The one invariant the share modal depends on: colour never changes the
    /// bytes, so a terminal selection copies the link intact.
    #[test]
    fn the_coloured_spans_reproduce_the_link_exactly() {
        for uri in [
            "vless://245abd35-7efa-4bc8-85d4-a04f3798329f@1.2.3.4:443?security=reality&sni=a.b&fp=chrome&sid=ab12#\u{1F1E9}\u{1F1EA} Frankfurt",
            "trojan://secret@example.com:8443?security=tls&sni=e.com#Node",
            "vmess://eyJhIjoiYiJ9",
            "ss://YWVzOnB3@[2001:db8::1]:8388#v6",
            "not-a-link",
            "",
        ] {
            assert_eq!(joined(uri), uri, "spans must reproduce {uri:?}");
        }
    }

    #[test]
    fn the_scheme_the_host_and_the_name_each_get_their_own_span() {
        let t = theme();
        let spans = highlight_link("vless://uuid@host.example:443?type=tcp#My Node", &t);
        // The scheme is its own bold span.
        assert_eq!(spans[0].content.as_ref(), "vless://");
        assert_eq!(spans[0].style.fg, Some(t.accent_bright));
        // The credential is coloured apart from the host.
        assert!(spans
            .iter()
            .any(|s| s.content.as_ref() == "uuid" && s.style.fg == Some(t.warn)));
        assert!(spans
            .iter()
            .any(|s| s.content.as_ref() == "host.example" && s.style.fg == Some(t.accent_bright)));
        assert!(spans
            .iter()
            .any(|s| s.content.as_ref() == "443" && s.style.fg == Some(t.info)));
        // The name (fragment) gets the ok colour and stands out.
        assert!(spans
            .iter()
            .any(|s| s.content.as_ref() == "My Node" && s.style.fg == Some(t.ok)));
    }

    #[test]
    fn a_string_without_a_scheme_is_one_plain_span() {
        let spans = highlight_link("just some text", &theme());
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].content.as_ref(), "just some text");
    }
}
