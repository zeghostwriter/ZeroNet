//! The signed, remotely-updatable domestic-SNI decoy list.
//!
//! The SNI decoy ([`zero_evasion::decoy`]) carries a server name the Iranian
//! filter is known to let through in place of the real one, drawn from a
//! curated pool ([`zero_evasion::domestic`]). That pool is compiled into the
//! app, which makes it the one thing in the decoy path that cannot change
//! without shipping a new build: the day the filter starts throttling a name
//! in it, every device is stuck with the old set until it updates.
//!
//! This module is the escape hatch. The maintainer publishes a short list of
//! extra decoy names on the `crowd-data` branch — `domestic-sni.txt`, one host
//! per line — signed with the same key as `verified.txt` ([`crate::sign`]).
//! The app fetches it over the same metered, filtered link as every other
//! feed ([`crate::feed`]), so the three guarantees there apply unchanged:
//!
//! * **Verified.** A freshly downloaded body is refused unless it matches the
//!   detached `domestic-sni.txt.sig` signature, so a CDN or a network in the
//!   middle cannot inject a name the filter *does* throttle (which would be a
//!   way to mark Zray's traffic rather than hide it).
//! * **Mirrored.** jsDelivr is the primary and GitHub raw the fallback, since
//!   the two are filtered at different times in Iran.
//! * **Cached, with an offline floor.** The last good list is kept on disk; a
//!   failed fetch leaves it in place, and a device that has never reached the
//!   list falls back to the bundled pool — [`cached`] returns nothing and the
//!   pick ([`zero_evasion::domestic::pick_from`]) uses the compiled-in names
//!   alone. The feed only ever *adds*, so it can never leave the decoy worse
//!   off than a build with no network at all.
//!
//! The list is small on purpose (a handful of names, capped by
//! [`zero_evasion::domestic::MAX_FEED_NAMES`]): a decoy pool wants a few good
//! hosts, not a directory, and a hostile but somehow-signed body still cannot
//! make a device hold more than the cap.

use std::path::Path;
use std::time::Duration;

use crate::feed::{fetch_feed, FeedResult, FeedSource};

/// The source id, also the cache file stem (`<id>.txt`). Kept to the
/// characters [`crate::feed`]'s `cache_stem` leaves untouched (lowercase
/// letters and a hyphen), so [`cached`] can read `<dir>/<ID>.txt` directly
/// and get the exact file [`refresh`] wrote.
pub const ID: &str = "domestic-sni";

/// The primary URL: jsDelivr, which tends to outlast GitHub raw in Iran.
const PRIMARY: &str =
    "https://cdn.jsdelivr.net/gh/zeghostwriter/ZeroNet@crowd-data/domestic-sni.txt";

/// The fallback URL on the other CDN, serving the same bytes.
const MIRROR: &str =
    "https://raw.githubusercontent.com/zeghostwriter/ZeroNet/crowd-data/domestic-sni.txt";

/// The feed this module fetches: the domestic-SNI list, signed and mirrored,
/// on the shared `crowd-data` branch beside `verified.txt`.
///
/// The signature URL points at jsDelivr (the primary), matching `verified.txt`
/// in [`crate::sources`]: a body served by the mirror is still checked against
/// the primary's `.sig`, so when jsDelivr is the host that is blocked the body
/// is treated as unverified and the cached list is used instead of trusting an
/// unchecked one.
pub fn source() -> FeedSource {
    FeedSource {
        id: ID.into(),
        url: PRIMARY.into(),
        tier: 0,
        sig_url: Some(format!("{PRIMARY}.sig")),
        mirrors: vec![MIRROR.into()],
    }
}

/// Fetch the domestic-SNI list into `cache_dir`, verifying its signature and
/// falling back to the cached copy when the network fails.
///
/// A thin wrapper over [`fetch_feed`]: all it adds is the fixed [`source`].
/// The host calls it while online (discovery does, since a search is already
/// an online, feed-fetching moment); `timeout` is the per-fetch deadline. The
/// returned [`FeedResult`] says what happened, for logging — the names are
/// read separately by [`cached`] at config-build time, which is usually
/// offline.
pub async fn refresh(cache_dir: &Path, timeout: Duration) -> FeedResult {
    fetch_feed(&source(), Some(cache_dir), timeout).await
}

/// The extra decoy names [`refresh`] last cached in `cache_dir`, parsed and
/// validated ([`zero_evasion::domestic::parse_feed`]).
///
/// Returns an empty vector when the list has never been fetched or the file
/// cannot be read or parsed — the caller then draws from the bundled pool
/// alone, so a missing or unreadable cache is the offline floor, not an error.
/// Only a cached body that passed signature verification is ever on disk (see
/// [`crate::feed`]), so this step is shape, not provenance.
pub fn cached(cache_dir: &Path) -> Vec<String> {
    // `ID` is a clean cache stem, so the body file is `<dir>/<ID>.txt`.
    match std::fs::read_to_string(cache_dir.join(format!("{ID}.txt"))) {
        Ok(body) => zero_evasion::domestic::parse_feed(&body),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The source is signed, mirrored across both CDNs, and HTTPS — the
    /// properties `fetch_feed` relies on to refuse a swapped body and to
    /// survive one CDN being filtered.
    #[test]
    fn the_source_is_signed_and_mirrored() {
        let source = source();
        assert_eq!(source.id, ID);
        assert!(source.url.starts_with("https://"));
        assert!(
            source
                .sig_url
                .as_deref()
                .is_some_and(|s| s.ends_with(".sig")),
            "the domestic-SNI list must be signed"
        );
        let mirror = source.mirrors.first().expect("needs a mirror");
        assert_ne!(mirror, &source.url);
        assert!(mirror.starts_with("https://"));
    }

    /// `cached` reads the exact file `refresh` writes (`<id>.txt`) and parses
    /// it; a missing cache is the offline floor, an empty vector, not an error.
    #[test]
    fn cached_reads_and_parses_the_cached_body() {
        let dir = std::env::temp_dir().join(format!(
            "zero-discovery-domestic-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        // Never fetched: the floor.
        assert!(cached(&dir).is_empty());

        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(format!("{ID}.txt")),
            "# extra decoy names\nnew.example.ir\nwww.speedtest.net\nalso.example.net\n",
        )
        .unwrap();
        // Parsed, with the comment skipped and the already-bundled host
        // dropped — exactly what `parse_feed` guarantees.
        assert_eq!(
            cached(&dir),
            vec!["new.example.ir".to_string(), "also.example.net".to_string()]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
