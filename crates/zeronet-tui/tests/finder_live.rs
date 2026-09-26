//! The config finder against the real public feeds and crowd rankings.
//!
//! Needs the internet (and, from a censored network, feeds that are
//! reachable), so it is ignored by default:
//!
//! ```text
//! cargo test -p zeronet-tui --test finder_live -- --ignored --nocapture
//! ```

use std::time::{Duration, Instant};

use zeronet_tui::finder::{self, FinderEvent, FinderRequest};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "uses the internet"]
async fn the_finder_finds_a_working_server_on_this_network() {
    let dir = std::env::temp_dir().join(format!("zeronet-finder-live-{}", std::process::id()));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let request = FinderRequest {
        cache_dir: Some(dir.clone()),
        want_alive: 1,
        max_seconds: 150,
        ..FinderRequest::default()
    };
    let started = Instant::now();
    let job = tokio::spawn(finder::run(request, tx, zero_discovery::CancellationToken::new()));
    let mut alive = Vec::new();
    let mut failed = 0;
    let mut done = None;
    while let Some(event) = tokio::time::timeout(Duration::from_secs(200), rx.recv()).await.unwrap() {
        match event {
            FinderEvent::Stage(stage) => println!("[{:>5.1}s] stage {stage}", started.elapsed().as_secs_f32()),
            FinderEvent::Alive { info, delay_ms, origin } => {
                println!(
                    "[{:>5.1}s] ALIVE {origin:?} {} {}/{}/{} {delay_ms} ms",
                    started.elapsed().as_secs_f32(),
                    info.name,
                    info.protocol,
                    info.transport,
                    info.security
                );
                alive.push(info);
            }
            FinderEvent::Failed { .. } => failed += 1,
            FinderEvent::Note(note) => println!("note: {note}"),
            FinderEvent::Progress(p) => println!("  progress {p:?}"),
            FinderEvent::Done { alive, reason } => {
                println!("[{:>5.1}s] done: {alive} alive ({reason}), {failed} known failed", started.elapsed().as_secs_f32());
                done = Some(alive);
                break;
            }
        }
    }
    job.await.unwrap();
    assert!(done.is_some(), "the search never finished");
    assert!(!alive.is_empty(), "no working server found");
    // Every find is a runnable share link.
    for info in &alive {
        zero_config::parse_link(&info.link).expect("found links parse");
    }
    let _ = std::fs::remove_dir_all(dir);
}
