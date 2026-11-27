//! MTU discovery for one resolver path, as pure (sans-IO) logic.
//!
//! Before a session can carry useful traffic the client has to learn two
//! numbers for the path through a given resolver: how many payload bytes it can
//! push *up* to the server inside one DNS question, and how many the server can
//! push *down* inside one TXT answer. Both are discovered the same way — send a
//! probe of a candidate size, see whether an untouched echo comes back — and
//! both are searched for with the same largest-value binary search.
//!
//! This module is only the arithmetic and the byte layouts: build a probe
//! payload, decide whether a response is a valid echo, and run the search given
//! a closure that performs one probe. The sockets, the timers, the retry
//! scheduling and the per-domain capacity caps live in the async wrapper, which
//! supplies the probe closure. Keeping it sans-IO is what lets the search and
//! the exact byte offsets be unit-tested without a network, and matched against
//! the Go client (`internal/client/mtu.go`) at the pinned release.
//!
//! # The two probe shapes
//!
//! Both probes carry a four-byte *code* the server must echo, so a stale or
//! forged answer for a different probe is ignored. The request also carries a
//! one-byte *mode* flag telling the server to answer raw (`0`) or base64 (`1`);
//! the same flag drives the client's response decoder.
//!
//! * **Upload probe.** The request payload is exactly the candidate size. The
//!   server answers `MTU_UP_RES` with a six-byte payload: the echoed code and
//!   the echoed size. A matching six bytes proves the question of that size
//!   survived the path intact.
//! * **Download probe.** The request asks the server to produce a *downstream*
//!   answer of a given size (written in the request at `[5:7]`); the request
//!   itself is only as big as it needs to be (`max(7, upload_mtu)`). The server
//!   answers `MTU_DOWN_RES` whose total length *is* the proof — if that many
//!   bytes came back, the path can carry that many down.
//!
//! Note the code sits at different offsets in request versus response: the
//! request reserves byte `[0]` for the mode flag so the code is at `[1:5]`; the
//! response has no mode byte, so the code is at `[0:4]` and the echoed size at
//! `[4:6]`.

#[cfg(test)]
mod tests;

use std::time::Duration;

use zero_protocol::masterdns::enums::{PACKET_MTU_DOWN_RES, PACKET_MTU_UP_RES};
use zero_protocol::masterdns::packet::{header_raw_size, max_header_raw_size, SESSION_ACCEPT_SIZE};

/// Length of the echoed probe code, in bytes.
pub const MTU_PROBE_CODE_LENGTH: usize = 4;
/// Request mode byte asking the server to answer with raw TXT bytes.
pub const MTU_PROBE_RAW_RESPONSE: u8 = 0;
/// Request mode byte asking the server to answer with base64 TXT text.
pub const MTU_PROBE_BASE64_REPLY: u8 = 1;

/// Hard ceiling on the upload search range, regardless of config, matching Go
/// `defaultUploadMaxCap`. A DNS question cannot usefully carry more than this
/// many payload bytes on any sane path.
pub const DEFAULT_UPLOAD_MAX_CAP: i32 = 512;
/// Absolute floor the upload search will not go below, matching Go
/// `minUploadMTUFloor`.
pub const MIN_UPLOAD_MTU_FLOOR: i32 = 10;
/// Absolute floor the download search will not go below: a download answer has
/// to be able to hold at least a full SESSION_ACCEPT payload. Matches Go
/// `minDownloadMTUFloor = VpnProto.SessionAcceptPayloadSize`.
pub const MIN_DOWNLOAD_MTU_FLOOR: i32 = SESSION_ACCEPT_SIZE as i32;

/// The sentinel session id a probe query carries before a session exists.
pub const PROBE_SENTINEL_SESSION_ID: u8 = 255;
/// The stream id every probe query carries.
pub const PROBE_STREAM_ID: u16 = 1;
/// The sequence number every probe query carries.
pub const PROBE_SEQUENCE_NUM: u16 = 1;
/// The fragment id every probe query carries (probes are never fragmented).
pub const PROBE_FRAGMENT_ID: u8 = 0;
/// The total-fragments field every probe query carries.
pub const PROBE_TOTAL_FRAGMENTS: u8 = 1;

/// How many upload-probe attempts [`confirm_resolver_down`-style] liveness
/// checks make before declaring a resolver down, matching Go `confirmResolverDown`.
pub const CONFIRM_RESOLVER_DOWN_ATTEMPTS: u32 = 2;

/// The block size the packed-control-block batch math divides by, matching Go
/// `vpnproto.PackedControlBlockSize`.
pub const PACKED_CONTROL_BLOCK_SIZE: i32 = 7;

/// The slack a download answer leaves for its own header, measured as the gap
/// between the largest header any packet carries and the `MTU_DOWN_RES` header.
///
/// With the current protocol table both are 11 bytes, so this is `0`: the
/// requested download size and the expected answer length coincide. It is kept
/// as a computed value, not a baked constant, so it tracks the flag table if a
/// future type widens the maximum header. Mirrors Go `mtuDownResponseReserve`.
pub fn mtu_down_response_reserve() -> usize {
    max_header_raw_size().saturating_sub(header_raw_size(PACKET_MTU_DOWN_RES))
}

/// The on-the-wire download size a probe for `download_mtu` asks the server to
/// produce: the requested MTU plus the header reserve. `0` for a non-positive
/// input. Mirrors Go `effectiveDownloadMTUProbeSize`.
pub fn effective_download_mtu_probe_size(download_mtu: i32) -> i32 {
    if download_mtu <= 0 {
        return 0;
    }
    download_mtu + mtu_down_response_reserve() as i32
}

/// Build a probe request payload of `length` bytes: mode flag at `[0]`, the
/// big-endian code at `[1:5]`, the rest left zero. Returns `None` if `length`
/// is too small to hold the mode flag and the code (fewer than five bytes),
/// which the callers guard against. Mirrors Go `buildMTUProbePayload`.
pub fn build_probe_payload(length: i32, base64: bool, code: u32) -> Option<Vec<u8>> {
    if length < (1 + MTU_PROBE_CODE_LENGTH) as i32 {
        return None;
    }
    let mut payload = vec![0u8; length as usize];
    payload[0] = if base64 {
        MTU_PROBE_BASE64_REPLY
    } else {
        MTU_PROBE_RAW_RESPONSE
    };
    payload[1..1 + MTU_PROBE_CODE_LENGTH].copy_from_slice(&code.to_be_bytes());
    Some(payload)
}

/// Build an upload-probe request payload. The payload length *is* the candidate
/// upload size, so a server that echoes it proves a question of that size made
/// it across. Returns `None` for a size below the five-byte minimum. Mirrors the
/// payload build inside Go `sendUploadMTUProbe`.
pub fn build_upload_probe_payload(mtu_size: i32, base64: bool, code: u32) -> Option<Vec<u8>> {
    build_probe_payload(mtu_size, base64, code)
}

/// A built download probe: the request bytes to send and the exact answer
/// length the server should produce (and that [`validate_download_response`]
/// must see).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadProbe {
    pub payload: Vec<u8>,
    pub effective_size: i32,
}

/// Build a download-probe request. `upload_mtu` is the already-settled upload
/// size, used only to size the request (`max(7, upload_mtu)`); `download_mtu` is
/// the candidate being probed. The requested answer size is written big-endian
/// at `[5:7]`. Returns `None` if the effective answer size is below the download
/// floor, or if the request is somehow too small to build. Mirrors the payload
/// build inside Go `sendDownloadMTUProbe`.
pub fn build_download_probe_payload(
    download_mtu: i32,
    upload_mtu: i32,
    base64: bool,
    code: u32,
) -> Option<DownloadProbe> {
    let effective_size = effective_download_mtu_probe_size(download_mtu);
    if effective_size < MIN_DOWNLOAD_MTU_FLOOR {
        return None;
    }
    let request_len = ((1 + MTU_PROBE_CODE_LENGTH + 2) as i32).max(upload_mtu);
    let mut payload = build_probe_payload(request_len, base64, code)?;
    let off = 1 + MTU_PROBE_CODE_LENGTH;
    payload[off..off + 2].copy_from_slice(&(effective_size as u16).to_be_bytes());
    Some(DownloadProbe {
        payload,
        effective_size,
    })
}

/// Whether a parsed response is a valid echo of an upload probe: the right type,
/// a six-byte payload, the echoed code equal to the one we sent, and the echoed
/// size equal to the candidate we probed. Mirrors the checks in Go
/// `sendUploadMTUProbe`.
pub fn validate_upload_response(
    packet_type: u8,
    payload: &[u8],
    expected_code: u32,
    probed_size: i32,
) -> bool {
    if packet_type != PACKET_MTU_UP_RES {
        return false;
    }
    if payload.len() != 6 {
        return false;
    }
    let code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if code != expected_code {
        return false;
    }
    let size = u16::from_be_bytes([payload[4], payload[5]]) as i32;
    size == probed_size
}

/// Whether a parsed response is a valid echo of a download probe: the right
/// type, a payload whose *length* equals the requested effective size, the
/// echoed code equal to the one we sent, and the echoed size equal to the
/// requested effective size. The length check is the real proof the path can
/// carry that many bytes down. Mirrors the checks in Go `sendDownloadMTUProbe`.
pub fn validate_download_response(
    packet_type: u8,
    payload: &[u8],
    expected_code: u32,
    effective_size: i32,
) -> bool {
    if packet_type != PACKET_MTU_DOWN_RES {
        return false;
    }
    if payload.len() != effective_size as usize {
        return false;
    }
    if payload.len() < 1 + MTU_PROBE_CODE_LENGTH + 1 {
        return false;
    }
    let code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if code != expected_code {
        return false;
    }
    let size = u16::from_be_bytes([payload[4], payload[5]]) as i32;
    size == effective_size
}

/// The result of one probe attempt, as seen by the search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The candidate size echoed back cleanly, with this round-trip time.
    Pass(Duration),
    /// The candidate did not echo (loss, truncation, or a transport error).
    Fail,
    /// The caller is shutting down; abandon the search.
    Cancelled,
}

enum CheckResult {
    Ok(Duration),
    Fail,
    Cancel,
}

/// Run up to `retries` attempts at one candidate; the first clean echo wins and
/// its RTT is kept. `is_retry` is passed to the probe so it can log or pace a
/// repeat differently. Mirrors the inner `check` closure of Go `binarySearchMTU`.
fn check<F>(value: i32, retries: u32, probe: &mut F) -> CheckResult
where
    F: FnMut(i32, bool) -> ProbeOutcome,
{
    for attempt in 0..retries {
        match probe(value, attempt > 0) {
            ProbeOutcome::Cancelled => return CheckResult::Cancel,
            ProbeOutcome::Pass(rtt) => return CheckResult::Ok(rtt),
            ProbeOutcome::Fail => {}
        }
    }
    CheckResult::Fail
}

/// Find the largest MTU in `[max(min_value, min_floor), max_value]` that a probe
/// still echoes cleanly, returning it with the RTT of its winning probe, or
/// `None` if even the floor fails (or the search is cancelled).
///
/// The search treats "size `s` echoes" as a monotone predicate (larger sizes
/// are the ones that fail), so it is an ordinary largest-true binary search with
/// one optimisation: it tries the ceiling first, since a healthy path usually
/// accepts the maximum outright. Each candidate is given up to `retries`
/// attempts. Mirrors Go `binarySearchMTU`.
///
/// A `Cancelled` from any probe abandons the search and returns `None`,
/// matching the Go loop's context-cancellation guard (which likewise discards
/// any best-so-far).
pub fn binary_search_mtu<F>(
    min_value: i32,
    max_value: i32,
    min_floor: i32,
    retries: u32,
    mut probe: F,
) -> Option<(i32, Duration)>
where
    F: FnMut(i32, bool) -> ProbeOutcome,
{
    if max_value <= 0 {
        return None;
    }
    let low = min_value.max(min_floor);
    let high = max_value;
    if high < low {
        return None;
    }

    // Try the ceiling first: a healthy path accepts it and we are done.
    match check(high, retries, &mut probe) {
        CheckResult::Ok(rtt) => return Some((high, rtt)),
        CheckResult::Cancel => return None,
        CheckResult::Fail => {}
    }
    if low == high {
        return None;
    }

    // Establish the floor; if even it fails there is no working MTU.
    let mut best = low;
    let mut best_rtt = match check(low, retries, &mut probe) {
        CheckResult::Ok(rtt) => rtt,
        _ => return None,
    };

    // Largest-true binary search over the open interval between floor and ceiling.
    let mut left = low + 1;
    let mut right = high - 1;
    while left <= right {
        let mid = (left + right) / 2;
        match check(mid, retries, &mut probe) {
            CheckResult::Ok(rtt) => {
                best = mid;
                best_rtt = rtt;
                left = mid + 1;
            }
            CheckResult::Fail => {
                right = mid - 1;
            }
            CheckResult::Cancel => return None,
        }
    }
    Some((best, best_rtt))
}

/// The effective ceiling for the upload search: the configured maximum, but
/// never above [`DEFAULT_UPLOAD_MAX_CAP`], and that cap when the config leaves
/// it at or below zero. Mirrors the `maxLimit` clamp in Go `testUploadMTU`.
pub fn upload_max_limit(cfg_max_upload_mtu: i32) -> i32 {
    if cfg_max_upload_mtu <= 0 || cfg_max_upload_mtu > DEFAULT_UPLOAD_MAX_CAP {
        DEFAULT_UPLOAD_MAX_CAP
    } else {
        cfg_max_upload_mtu
    }
}

/// The smallest upload result worth accepting: the configured minimum, but never
/// below [`MIN_UPLOAD_MTU_FLOOR`]. A search result under this is rejected.
pub fn upload_accept_floor(cfg_min_upload_mtu: i32) -> i32 {
    MIN_UPLOAD_MTU_FLOOR.max(cfg_min_upload_mtu)
}

/// The smallest download result worth accepting: the configured minimum, but
/// never below [`MIN_DOWNLOAD_MTU_FLOOR`]. A search result under this is rejected.
pub fn download_accept_floor(cfg_min_download_mtu: i32) -> i32 {
    MIN_DOWNLOAD_MTU_FLOOR.max(cfg_min_download_mtu)
}

/// The mean of the probe round-trip times that were actually measured
/// (positive); zero if none were. Used as the connection's resolve time.
/// Mirrors Go `averageMTUProbeRTT`.
pub fn average_mtu_probe_rtt(values: &[Duration]) -> Duration {
    let mut sum = Duration::ZERO;
    let mut count: u32 = 0;
    for &value in values {
        if value.is_zero() {
            continue;
        }
        sum += value;
        count += 1;
    }
    if count == 0 {
        Duration::ZERO
    } else {
        sum / count
    }
}

/// The per-packet crypto overhead to reserve, by encryption method: 16 bytes
/// for method 2, 28 for the AEAD methods 3/4/5, none otherwise. Mirrors Go
/// `mtuCryptoOverhead`.
pub fn mtu_crypto_overhead(method: i32) -> i32 {
    match method {
        2 => 16,
        3..=5 => 28,
        _ => 0,
    }
}

/// The usable upload payload size after reserving crypto overhead: the upload
/// MTU minus the overhead, floored at 64, and never larger than the upload MTU
/// itself. Zero for a non-positive upload MTU. Mirrors Go `computeSafeUploadMTU`.
///
/// Note the order the Go code uses, which this keeps: the 64-byte floor is
/// applied first, then the result is clamped back down to `upload_mtu`. So for a
/// tiny `upload_mtu` under 64 the floor would overshoot and the clamp returns
/// `upload_mtu` unchanged.
pub fn compute_safe_upload_mtu(upload_mtu: i32, crypto_overhead: i32) -> i32 {
    if upload_mtu <= 0 {
        return 0;
    }
    let mut safe = upload_mtu - crypto_overhead;
    if safe < 64 {
        safe = 64;
    }
    if safe > upload_mtu {
        return upload_mtu;
    }
    safe
}

/// How many packed control blocks fit in one batch for a given upload MTU:
/// `percent` of the MTU, divided by the block size, clamped to `[1, absolute_max]`.
/// All divisions truncate. Mirrors Go `vpnproto.CalculateMaxPackedBlocks`,
/// called with `percent = 80` and `absolute_max = MaxPacketsPerBatch`.
pub fn max_packed_blocks(mtu: i32, percent: i32, absolute_max: i32) -> i32 {
    let mtu = mtu.max(1);
    let percent = percent.max(30);
    let effective = (mtu * percent) / 100;
    ((effective / PACKED_CONTROL_BLOCK_SIZE).max(1))
        .min(absolute_max)
        .max(1)
}

/// The per-attempt timeout a resolver-liveness check uses: 350ms by default, or
/// a third of a sub-second window, clamped to `[200ms, 1s]`. Mirrors the timeout
/// math in Go `confirmResolverDown`.
pub fn confirm_resolver_down_timeout(window: Duration) -> Duration {
    let mut timeout = Duration::from_millis(350);
    if window > Duration::ZERO && window < Duration::from_secs(1) {
        timeout = window / 3;
    }
    if timeout < Duration::from_millis(200) {
        timeout = Duration::from_millis(200);
    }
    if timeout > Duration::from_secs(1) {
        timeout = Duration::from_secs(1);
    }
    timeout
}

/// The probe size a resolver-liveness check uses: the current synced upload MTU
/// clamped to `[32, 96]`. Mirrors the `mtuSize` clamp in Go `confirmResolverDown`.
pub fn confirm_resolver_down_probe_size(synced_upload_mtu: i32) -> i32 {
    synced_upload_mtu.clamp(32, 96)
}
