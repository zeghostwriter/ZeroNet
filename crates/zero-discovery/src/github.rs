//! Finding config lists on GitHub.
//!
//! Many people publish free configs as a text file in a GitHub repository
//! that a scheduled job rewrites every few minutes or hours. The well-known
//! ones are in `deploy/crowd/sources.json`, but new ones appear every week and
//! old ones go quiet. The harvest (`zeronet-harvest --github-state`) uses this
//! module to keep up, the same way it keeps up with Telegram channels:
//!
//! 1. Ask GitHub's search for repositories about configs that were pushed to
//!    in the last few days ([`search_url`], [`parse_search`]).
//! 2. For a repository it has not seen before, list its files once
//!    ([`tree_url`]) and pick the few that look like config lists
//!    ([`pick_files`]): plain text, a sensible size, a name such as
//!    `mix.txt` or `sub`. Their raw addresses ([`raw_url`]) are what is kept.
//! 3. Every config in those files is tested with everything else. The harvest
//!    then notes, per file, how many servers in it actually worked
//!    ([`GithubState::record`]).
//! 4. A file that has had nothing working for [`FORGET_AFTER_SECS`] is
//!    dropped ([`GithubState::keep`]), and the files with the most working
//!    servers are read first next time ([`GithubState::ranked`]).
//!
//! Everything here is plain parsing and bookkeeping, so it is tested without
//! the network. The files are untrusted: their links go through the same
//! tests as every other feed before anyone sees them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What the search asks for. Each line is one search request, limited to
/// repositories pushed since a date the caller adds (see [`search_url`]).
pub const QUERIES: &[&str] = &[
    "v2ray config",
    "v2ray configs free",
    "vless reality",
    "v2ray collector",
    "proxy configs iran",
    "topic:v2ray-config",
];

/// A file that has had no working server for this long is forgotten.
pub const FORGET_AFTER_SECS: i64 = 14 * 24 * 3600;
/// A file found this recently is kept even before anything in it has worked:
/// it gets a few runs to prove itself.
const GRACE_SECS: i64 = 2 * 24 * 3600;
/// Files picked from one repository at most.
pub const FILES_PER_REPO: usize = 3;
/// Smallest and largest file worth reading. Below, it holds a handful of
/// configs at best; above, it is an archive nobody keeps up to date.
const MIN_FILE_BYTES: u64 = 512;
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// One repository the search returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    /// `owner/name`.
    pub full_name: String,
    pub default_branch: String,
}

/// The search request for `query`, limited to repositories pushed on or after
/// `since` (`YYYY-MM-DD`), most recently updated first.
pub fn search_url(query: &str, since: &str) -> String {
    let q = format!("{query} pushed:>={since}");
    let q: String = url::form_urlencoded::byte_serialize(q.as_bytes()).collect();
    format!("https://api.github.com/search/repositories?q={q}&sort=updated&order=desc&per_page=30")
}

/// The repositories in one search answer. Forks and archived repositories
/// are left out: a fork's list is a stale copy, an archived one never moves.
pub fn parse_search(body: &str) -> Vec<Repo> {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    value["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|item| !item["fork"].as_bool().unwrap_or(false))
        .filter(|item| !item["archived"].as_bool().unwrap_or(false))
        .filter_map(|item| {
            let full_name = item["full_name"].as_str()?;
            let branch = item["default_branch"].as_str().unwrap_or("main");
            valid_repo_name(full_name).then(|| Repo {
                full_name: full_name.to_string(),
                default_branch: branch.to_string(),
            })
        })
        .collect()
}

/// `owner/name` made only of the characters GitHub allows, so it can go into
/// a URL path as it is.
fn valid_repo_name(name: &str) -> bool {
    let mut parts = name.split('/');
    let ok = |part: Option<&str>| {
        part.is_some_and(|p| {
            !p.is_empty()
                && p != "."
                && p != ".."
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
    };
    ok(parts.next()) && ok(parts.next()) && parts.next().is_none()
}

/// The request that lists every file of `repo` on its default branch.
pub fn tree_url(repo: &Repo) -> String {
    let branch: String =
        url::form_urlencoded::byte_serialize(repo.default_branch.as_bytes()).collect();
    format!(
        "https://api.github.com/repos/{}/git/trees/{branch}?recursive=1",
        repo.full_name
    )
}

/// The address the content of `path` in `repo` is served from, with every
/// path segment escaped.
pub fn raw_url(repo: &Repo, path: &str) -> String {
    let escape = |s: &str| -> String {
        percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC)
            .to_string()
            .replace("%2E", ".")
            .replace("%2D", "-")
            .replace("%5F", "_")
    };
    let path: Vec<String> = path.split('/').map(escape).collect();
    format!(
        "https://raw.githubusercontent.com/{}/{}/{}",
        repo.full_name,
        escape(&repo.default_branch),
        path.join("/")
    )
}

/// How much a file's path looks like a list of configs: 0 for "not at all",
/// higher for better. The words are what these repositories call their
/// lists; a file that names one protocol scores lower than a mixed list,
/// because one mixed list covers what several single-protocol ones do.
fn score(path: &str) -> u32 {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    // Code, docs, data the repository uses itself, and anything hidden.
    let ext = name.rsplit_once('.').map(|(_, ext)| ext).unwrap_or("");
    if !matches!(ext, "" | "txt" | "sub" | "list" | "b64" | "base64") {
        return 0;
    }
    if lower.split('/').any(|part| {
        part.starts_with('.')
            || matches!(
                part,
                "node_modules"
                    | "test"
                    | "tests"
                    | "docs"
                    | "src"
                    | "scripts"
                    | "deploy"
                    | "archive"
                    | "old"
            )
    }) {
        return 0;
    }
    if matches!(
        name,
        "license" | "readme" | "requirements.txt" | "robots.txt"
    ) {
        return 0;
    }
    let mut points = 0;
    for (word, worth) in [
        ("mix", 6),
        ("all", 5),
        ("sub", 4),
        ("config", 4),
        ("tested", 3),
        ("iran", 3),
        ("reality", 3),
        ("v2ray", 2),
        ("vless", 2),
        ("trojan", 1),
        ("vmess", 1),
        ("hysteria", 1),
        ("tuic", 1),
        ("proxy", 1),
    ] {
        if lower.contains(word) {
            points += worth;
        }
    }
    points
}

/// The paths in a tree answer worth reading, best first, at most `max`.
pub fn pick_files(tree_body: &str, max: usize) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<Value>(tree_body) else {
        return Vec::new();
    };
    let mut picked: Vec<(u32, &str)> = value["tree"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|entry| entry["type"].as_str() == Some("blob"))
        .filter(|entry| {
            entry["size"]
                .as_u64()
                .is_some_and(|size| (MIN_FILE_BYTES..=MAX_FILE_BYTES).contains(&size))
        })
        .filter_map(|entry| {
            let path = entry["path"].as_str()?;
            let points = score(path);
            (points > 0).then_some((points, path))
        })
        .collect();
    // Best first; between equals, the shorter path (nearer the top of the
    // repository, usually the main list rather than a per-country split).
    picked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.len().cmp(&b.1.len())));
    // Many repositories publish each list twice, as text and as base64
    // (`all.txt` and `all_base64.txt`): one copy is enough.
    let mut lists: Vec<String> = Vec::new();
    let mut paths = Vec::new();
    for (_, path) in picked {
        let list = same_list(path);
        if !lists.contains(&list) {
            lists.push(list);
            paths.push(path.to_string());
        }
        if paths.len() == max {
            break;
        }
    }
    paths
}

/// `path` with the marks of an encoding taken out, so the text and the
/// base64 copy of one list come out the same: `Sub1_base64.txt` and
/// `Sub1.txt` are both `sub1`.
fn same_list(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    let lower = lower.strip_suffix(".txt").unwrap_or(&lower);
    let mut list = lower.to_string();
    for mark in ["base64", "b64"] {
        list = list.replace(mark, "");
    }
    list.retain(|c| !matches!(c, '_' | '-' | '.'));
    list
}

/// What the harvest remembers about one file between runs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileState {
    /// `owner/name` of the repository it is in.
    pub repo: String,
    /// Unix seconds of the run that found the file.
    pub found: i64,
    /// Unix seconds of the last run in which a server from it worked; 0 for
    /// never.
    #[serde(default)]
    pub worked: i64,
    /// Servers from it that worked in that run.
    #[serde(default)]
    pub alive: usize,
}

/// `github-state.json`: the files found so far, by raw address, and the
/// repositories already looked into (so their files are not listed again).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GithubState {
    #[serde(default)]
    pub files: BTreeMap<String, FileState>,
    /// `owner/name` → Unix seconds it was last looked into.
    #[serde(default)]
    pub repos: BTreeMap<String, i64>,
}

impl GithubState {
    /// Whether `repo` was looked into within [`FORGET_AFTER_SECS`].
    pub fn knows_repo(&self, repo: &str, now: i64) -> bool {
        self.repos
            .get(repo)
            .is_some_and(|seen| now - seen < FORGET_AFTER_SECS)
    }

    /// Note a repository looked into now and the files picked from it.
    pub fn add_repo(&mut self, repo: &str, files: &[String], now: i64) {
        self.repos.insert(repo.to_string(), now);
        for url in files {
            self.files.entry(url.clone()).or_insert_with(|| FileState {
                repo: repo.to_string(),
                found: now,
                worked: 0,
                alive: 0,
            });
        }
    }

    /// Note that `alive` servers from the file at `url` worked in this run.
    pub fn record(&mut self, url: &str, alive: usize, now: i64) {
        if let Some(file) = self.files.get_mut(url) {
            file.alive = alive;
            if alive > 0 {
                file.worked = now;
            }
        }
    }

    /// Drop what is no longer worth reading: files with nothing working for
    /// [`FORGET_AFTER_SECS`] (new ones get [`GRACE_SECS`] first), and
    /// repositories not looked into for as long, so a quiet repository that
    /// wakes up is listed again.
    pub fn keep(&mut self, now: i64) {
        self.files.retain(|_, file| {
            let last = file.worked.max(file.found);
            let quiet_for = now - last;
            if file.worked == 0 {
                now - file.found < GRACE_SECS
            } else {
                quiet_for < FORGET_AFTER_SECS
            }
        });
        self.repos.retain(|_, seen| now - *seen < FORGET_AFTER_SECS);
    }

    /// The files' addresses, the ones with the most working servers first,
    /// then the newest; at most `max`.
    pub fn ranked(&self, max: usize) -> Vec<String> {
        let mut files: Vec<(&String, &FileState)> = self.files.iter().collect();
        files.sort_by(|a, b| b.1.alive.cmp(&a.1.alive).then(b.1.found.cmp(&a.1.found)));
        files
            .into_iter()
            .take(max)
            .map(|(url, _)| url.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> Repo {
        Repo {
            full_name: "someone/free-configs".into(),
            default_branch: "main".into(),
        }
    }

    #[test]
    fn the_search_asks_for_recent_pushes_and_skips_forks_and_archives() {
        let url = search_url("vless reality", "2026-10-05");
        assert!(url.starts_with("https://api.github.com/search/repositories?q="));
        assert!(url.contains("vless+reality+pushed%3A%3E%3D2026-10-05"));
        assert!(url.contains("sort=updated"));
        let body = r#"{"items": [
            {"full_name": "a/one", "default_branch": "master", "fork": false},
            {"full_name": "b/two", "fork": true},
            {"full_name": "c/three", "archived": true},
            {"full_name": "bad name/../x"},
            {"full_name": "d/four"}
        ]}"#;
        let repos = parse_search(body);
        assert_eq!(
            repos,
            vec![
                Repo {
                    full_name: "a/one".into(),
                    default_branch: "master".into()
                },
                Repo {
                    full_name: "d/four".into(),
                    default_branch: "main".into()
                },
            ]
        );
        assert!(parse_search("not json").is_empty());
        assert!(parse_search(r#"{"message": "API rate limit exceeded"}"#).is_empty());
    }

    #[test]
    fn config_lists_are_picked_and_code_and_docs_are_not() {
        let body = r#"{"tree": [
            {"path": "README.md", "type": "blob", "size": 4000},
            {"path": "main.py", "type": "blob", "size": 4000},
            {"path": "configs/mix.txt", "type": "blob", "size": 90000},
            {"path": "sub/vless", "type": "blob", "size": 50000},
            {"path": "configs/by-country/de/mix.txt", "type": "blob", "size": 9000},
            {"path": ".github/workflows/run.yml", "type": "blob", "size": 900},
            {"path": "configs", "type": "tree"},
            {"path": "tiny.txt", "type": "blob", "size": 20},
            {"path": "huge-all.txt", "type": "blob", "size": 90000000},
            {"path": "requirements.txt", "type": "blob", "size": 600},
            {"path": "node_modules/x/sub.txt", "type": "blob", "size": 9000},
            {"path": "configs/mix_base64.txt", "type": "blob", "size": 120000},
            {"path": "nginx/proxy-config.conf", "type": "blob", "size": 9000}
        ]}"#;
        let picked = pick_files(body, 3);
        assert_eq!(
            picked,
            vec![
                "configs/mix.txt",
                "configs/by-country/de/mix.txt",
                "sub/vless"
            ]
        );
        assert_eq!(pick_files(body, 1), vec!["configs/mix.txt"]);
        assert!(pick_files("{}", 3).is_empty());
    }

    #[test]
    fn raw_addresses_are_escaped() {
        assert_eq!(
            raw_url(&repo(), "configs/mix.txt"),
            "https://raw.githubusercontent.com/someone/free-configs/main/configs/mix.txt"
        );
        assert_eq!(
            raw_url(&repo(), "sub/all configs#1.txt"),
            "https://raw.githubusercontent.com/someone/free-configs/main/sub/all%20configs%231.txt"
        );
        assert_eq!(
            tree_url(&repo()),
            "https://api.github.com/repos/someone/free-configs/git/trees/main?recursive=1"
        );
    }

    #[test]
    fn files_that_stop_working_are_forgotten_and_the_best_come_first() {
        let day = 24 * 3600;
        let now = 100 * day;
        let mut state = GithubState::default();
        state.add_repo("a/one", &["u1".into(), "u2".into()], now - 20 * day);
        state.add_repo("b/two", &["u3".into()], now - day);
        state.add_repo("c/three", &["u4".into()], now - 3 * day);
        state.record("u1", 40, now - 20 * day); // worked long ago only
        state.record("u2", 7, now);
        state.record("u3", 0, now); // new, nothing yet: in its grace
        state.record("unknown", 5, now); // not ours: ignored
        state.keep(now);
        let kept: Vec<&str> = state.files.keys().map(String::as_str).collect();
        // u1 has been quiet 20 days; u4 never worked and is past its grace.
        assert_eq!(kept, vec!["u2", "u3"]);
        assert_eq!(state.ranked(10), vec!["u2", "u3"]);
        assert_eq!(state.ranked(1), vec!["u2"]);
        // a/one was looked into 20 days ago: listed again next time.
        assert!(!state.knows_repo("a/one", now));
        assert!(state.knows_repo("b/two", now));
        // A repository found again does not reset a file it already has.
        state.add_repo("b/two", &["u3".into()], now);
        assert_eq!(state.files["u3"].found, now - day);
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(serde_json::from_str::<GithubState>(&json).unwrap(), state);
    }
}
