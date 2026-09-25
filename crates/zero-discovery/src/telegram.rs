//! Configs posted in Iranian Telegram channels.
//!
//! Many Persian-language channels post working configs for anyone to use.
//! Their public web preview, `https://t.me/s/<channel>`, shows the latest
//! posts as HTML without an account or API key. This module reads those
//! pages: the share links in the posts, whether the channel is Persian, the
//! other channels it mentions (so the list can grow by itself), and where
//! the next page of older posts starts.
//!
//! The crawl itself lives in the `zeronet-harvest` binary.

/// The web preview of a channel's latest posts, or of the posts before
/// `before` (a post number).
pub fn page_url(channel: &str, before: Option<u64>) -> String {
    match before {
        Some(id) => format!("https://t.me/s/{channel}?before={id}"),
        None => format!("https://t.me/s/{channel}"),
    }
}

/// Whether `name` is a valid public channel username.
pub fn valid_channel(name: &str) -> bool {
    (5..=32).contains(&name.len())
        && name.as_bytes()[0].is_ascii_alphabetic()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// The page as text: every tag becomes a line break (so a post's lines and
/// a link inside `<code>` stand on their own) and HTML entities are decoded
/// (posts escape `&` in links as `&amp;`). Ready for
/// [`crate::link::extract_links`] and [`listed_names`].
pub fn page_text(html: &str) -> String {
    let mut text = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => {
                in_tag = false;
                text.push('\n');
            }
            _ if !in_tag => text.push(c),
            _ => {}
        }
    }
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#036;", "$")
}

/// How much Persian a page contains: the letters Persian has and Arabic
/// does not (پ چ ژ گ, and the Persian forms of kaf and yeh), counted. An
/// Arabic, Russian or Chinese channel scores zero.
pub fn persian_score(text: &str) -> usize {
    text.chars()
        .filter(|c| matches!(c, 'پ' | 'چ' | 'ژ' | 'گ' | 'ک' | 'ی'))
        .count()
}

/// A page that reads as Persian.
pub const PERSIAN_MIN: usize = 30;

/// Channels a page mentions by `@name` or a `t.me/name` link, lower-cased,
/// without `channel` itself.
pub fn mentions(html: &str, channel: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let bytes = html.as_bytes();
    let mut push = |name: &str| {
        let name = name.to_ascii_lowercase();
        if valid_channel(&name) && name != channel && !out.contains(&name) {
            out.push(name);
        }
    };
    let take_name = |from: usize| -> &str {
        let end = html[from..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .map_or(html.len(), |n| from + n);
        &html[from..end]
    };
    for (at, _) in html.match_indices('@') {
        // `@name` in text, not an e-mail address.
        let prev_ok = at == 0 || !bytes[at - 1].is_ascii_alphanumeric();
        if prev_ok {
            push(take_name(at + 1));
        }
    }
    for (at, pattern) in html.match_indices("t.me/") {
        let name = take_name(at + pattern.len());
        // `t.me/s/…`, `t.me/joinchat/…`, `t.me/+…` are not channel names.
        if !matches!(name, "s" | "joinchat" | "addlist" | "proxy" | "socks") {
            push(name);
        }
    }
    out
}

/// Whether a mentioned channel is worth a look: its name says VPN or
/// configs. Keeps the crawl on topic and small.
pub fn looks_like_config_channel(name: &str) -> bool {
    const WORDS: [&str; 18] = [
        "vpn", "v2ray", "v2ry", "v2rng", "config", "conf", "proxy", "vless", "vmess", "trojan",
        "reality", "fars", "pars", "iran", "shekan", "filter", "free", "net",
    ];
    let name = name.to_ascii_lowercase();
    WORDS.iter().any(|w| name.contains(w))
}

/// Names in a list post such as MahsaNet's monthly thank-you list of
/// server donors (`2. V2rayBaz (~986 TB)`), as channel usernames to try:
/// a one-word name as is, a name of several words joined plain and with
/// underscores. Anonymous donors, shown as hex ids, are skipped. Many
/// donors have no public channel; the crawl finds out which do.
pub fn listed_names(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |name: String| {
        if valid_channel(&name) && !is_hex_id(&name) && !out.contains(&name) {
            out.push(name);
        }
    };
    for line in text.lines() {
        let line = line.trim();
        // "12. Name (~183 TB)" or "12) Name – 183 TB": a numbered entry.
        let Some(rest) = line
            .split_once(['.', ')', '-'])
            .filter(|(n, _)| !n.is_empty() && n.trim().chars().all(|c| c.is_ascii_digit()))
            .map(|(_, rest)| rest)
        else {
            continue;
        };
        let name_part = rest.split(['(', '~', '–', '|']).next().unwrap_or("");
        let words: Vec<String> = name_part
            .split_whitespace()
            .filter(|w| w.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
            .map(str::to_ascii_lowercase)
            .collect();
        match words.len() {
            0 => {}
            1 => push(words[0].clone()),
            _ => {
                push(words.concat());
                push(words.join("_"));
            }
        }
    }
    out
}

/// An anonymous id such as `9127d869e2354a`, not a name.
fn is_hex_id(name: &str) -> bool {
    name.len() >= 12 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The oldest post number on the page, for fetching the page before it.
pub fn oldest_post(html: &str, channel: &str) -> Option<u64> {
    let marker = format!("data-post=\"{channel}/");
    let lower = html.to_ascii_lowercase();
    lower
        .match_indices(&marker.to_ascii_lowercase())
        .filter_map(|(at, m)| {
            let rest = &lower[at + m.len()..];
            let end = rest.find('"')?;
            rest[..end].parse::<u64>().ok()
        })
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"
        <div class="tgme_widget_message" data-post="ParsVPN/1201">
          <div class="tgme_widget_message_text">کانفیگ رایگان برای همه، اتصال پایدار روی همراه اول و ایرانسل
          <br/><code>vless://00000000-0000-0000-0000-000000000001@203.0.113.10:443?security=reality&amp;sni=www.google.com&amp;pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&amp;type=tcp#ParsVPN</code>
          <br/>کانال ما: @FarsVPN و https://t.me/v2ray_configs_fa
          <br/>ایمیل: support@example.com
          </div>
        </div>
        <div class="tgme_widget_message" data-post="ParsVPN/1188"></div>
        <a href="https://t.me/s/ParsVPN?before=1188">older</a>
    "#;

    #[test]
    fn links_come_out_of_the_page_unescaped() {
        let links = crate::link::extract_links(&page_text(PAGE));
        assert_eq!(links.len(), 1);
        assert!(links[0].contains("&sni=www.google.com&pbk="));
        assert!(crate::link::parse_candidate(&links[0]).is_ok());
    }

    #[test]
    fn persian_pages_are_told_apart() {
        assert!(persian_score(PAGE) >= 5);
        assert_eq!(persian_score("Бесплатные прокси для всех"), 0);
        assert_eq!(persian_score("خوادم مجانية للجميع"), 0);
    }

    #[test]
    fn mentioned_channels_are_found() {
        let found = mentions(PAGE, "parsvpn");
        assert!(found.contains(&"farsvpn".to_string()));
        assert!(found.contains(&"v2ray_configs_fa".to_string()));
        // Not the channel itself, not the `t.me/s/` path, not an e-mail.
        assert!(!found.contains(&"parsvpn".to_string()));
        assert!(!found.contains(&"s".to_string()));
        assert!(!found.iter().any(|n| n.contains("example")));
    }

    #[test]
    fn channel_names_are_checked() {
        assert!(valid_channel("parsvpn"));
        assert!(!valid_channel("vpn"));
        assert!(!valid_channel("1abcde"));
        assert!(!valid_channel("pars-vpn"));
        assert!(looks_like_config_channel("farsvpn"));
        assert!(looks_like_config_channel("V2rayNG_Iran"));
        assert!(!looks_like_config_channel("cooking_recipes"));
    }

    #[test]
    fn donor_lists_are_read_from_the_page() {
        let html = "<div class=\"tgme_widget_message_text\">سپاس<br/>1. V2rayBaz (~986 TB)<br/><b>2. teymur_vpn</b> (~254 TB)</div>";
        assert_eq!(
            listed_names(&page_text(html)),
            vec!["v2raybaz", "teymur_vpn"]
        );
    }

    #[test]
    fn donor_lists_give_names_to_try() {
        let post = "سپاس از اهداکنندگان این ماه\n\
                    1. Internet Azad (~1074 TB)\n\
                    2. V2rayBaz (~986 TB)\n\
                    3. Bahamestan باهمستان آزادی (~303 TB)\n\
                    8. 9127d869e2354a (~189 TB)\n\
                    22. mahsa_net (~54 TB)\n\
                    متن معمولی بدون شماره";
        let names = listed_names(post);
        assert_eq!(
            names,
            vec![
                "internetazad",
                "internet_azad",
                "v2raybaz",
                "bahamestan",
                "mahsa_net"
            ]
        );
    }

    #[test]
    fn older_pages_are_found() {
        assert_eq!(oldest_post(PAGE, "parsvpn"), Some(1188));
        assert_eq!(
            page_url("parsvpn", Some(1188)),
            "https://t.me/s/parsvpn?before=1188"
        );
    }
}
