//! The public config feeds a client searches, tiered by what measurement
//! from inside Iran showed. Tier 0 is this project's own tested (and signed)
//! list; tier 1 is fetched on every cold search that tier 0 did not
//! satisfy; tier 2 only when tier 1 fell short; tier 3 only when asked to
//! search harder. The Android app keeps the same list in `data/Sources.kt`.

use crate::feed::FeedSource;

const RAW: &str = "https://raw.githubusercontent.com";

/// A feed with its display name, for hosts that let the user switch feeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedSource {
    pub name: &'static str,
    pub source: FeedSource,
}

fn source(id: &str, name: &'static str, url: String, tier: u32, sig_url: Option<String>) -> NamedSource {
    NamedSource {
        name,
        source: FeedSource {
            id: id.into(),
            url,
            tier,
            sig_url,
        },
    }
}

/// Every built-in feed.
pub fn builtin() -> Vec<NamedSource> {
    let verified = "https://cdn.jsdelivr.net/gh/zeghostwriter/ZeroNet@crowd-data/verified.txt";
    vec![
        source("zeronet", "ZeroNet verified", verified.into(), 0, Some(format!("{verified}.sig"))),
        source("limilco", "liMilCo", format!("{RAW}/liMilCo/v2r/main/new_configs.txt"), 1, None),
        source("sinavm", "SVM", format!("{RAW}/sinavm/SVM/main/lite/subscriptions/xray/base64/mix"), 1, None),
        source(
            "anonymou3",
            "Multi Proxy (tested)",
            format!("{RAW}/4n0nymou3/multi-proxy-config-fetcher/main/configs/proxy_configs_tested.txt"),
            1,
            None,
        ),
        source("radikal", "0xRadikal", format!("{RAW}/0xRadikal/Free-v2ray-Configs/main/all/configs.txt"), 2, None),
        source("epodonios", "Epodonios", format!("{RAW}/Epodonios/v2ray-configs/main/All_Configs_Sub.txt"), 2, None),
        source("delta", "Delta-Kronecker", format!("{RAW}/Delta-Kronecker/V2ray-Config/main/config/all_configs.txt"), 3, None),
        source("mheidari", "mheidari98", format!("{RAW}/mheidari98/.proxy/main/all"), 3, None),
        source("f0rc3run", "F0rc3Run", format!("{RAW}/F0rc3Run/F0rc3Run/main/Best-Results/sub.txt"), 3, None),
    ]
}

/// The feeds to search: every built-in one up to `max_tier` not in `disabled`.
pub fn enabled(disabled: &[String], max_tier: u32) -> Vec<FeedSource> {
    builtin()
        .into_iter()
        .filter(|named| named.source.tier <= max_tier && !disabled.iter().any(|id| id == &named.source.id))
        .map(|named| named.source)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_the_verified_list_is_signed_and_first() {
        let all = builtin();
        let mut ids: Vec<_> = all.iter().map(|n| n.source.id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), all.len());
        assert_eq!(all[0].source.tier, 0);
        assert!(all[0].source.sig_url.is_some());
        assert!(all.iter().all(|n| n.source.url.starts_with("https://")));
    }

    #[test]
    fn disabled_feeds_and_higher_tiers_are_left_out() {
        let some = enabled(&["limilco".into()], 1);
        assert!(some.iter().all(|s| s.tier <= 1 && s.id != "limilco"));
        assert!(some.iter().any(|s| s.id == "zeronet"));
    }
}
