//! The local SOCKS handshake, as a pure (sans-IO) byte parser.
//!
//! A browser (or any SOCKS client) connects to the local listener and speaks
//! SOCKS4, SOCKS4a, or SOCKS5 to ask "please open a connection to host:port".
//! This module is the deterministic half of answering that: it is fed the raw
//! bytes the client sends, and it emits [`SocksAction`]s — bytes to write back,
//! an auth pass/fail signal for the rate limiter, and finally a `Connect` (or
//! `UdpAssociate`) carrying the parsed [`Target`], or a `Close`. It never
//! touches a socket, a clock, or a lock; the async listener feeds it bytes and
//! acts on what it emits.
//!
//! # Why a byte parser and not a reader
//!
//! The Go client reads the handshake with `io.ReadFull`, pulling exactly as
//! many bytes as each step needs straight off the socket. A sans-IO port can't
//! block on a socket, so instead the caller pushes whatever it has read so far
//! into [`SocksHandshake::push`] and the parser consumes as far as it can,
//! stopping cleanly when it needs more. Any bytes left after the handshake
//! finishes (the start of the stream's own data) are handed back by
//! [`SocksHandshake::take_remaining`], mirroring how `io.ReadFull` leaves the
//! rest in the socket for the data loop to read.
//!
//! # What it does not do
//!
//! It does not send the *success* reply. In the real client the SOCKS success
//! (or a later failure) is written only once the server confirms the stream
//! connected, so that reply is the stream manager's job, not the handshake's.
//! The parser only emits the error replies the Go code sends inline during the
//! handshake itself (bad command, auth failure, unsupported command).
//!
//! Ported from the Go client's `internal/client/socks_manager.go` handshake
//! path (`HandleSOCKS5`, `handleSOCKS5Request`, `handleSOCKS4Request`,
//! `handleSOCKSConnect`) at the pinned release `v2026.06.13.234407-7de2476`.

#[cfg(test)]
mod tests;

use zero_protocol::masterdns::socks::{
    Target, ADDRESS_TYPE_DOMAIN, ADDRESS_TYPE_IPV4, ADDRESS_TYPE_IPV6,
};

use zero_protocol::masterdns::enums::{
    PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED, PACKET_SOCKS5_AUTH_FAILED,
    PACKET_SOCKS5_COMMAND_UNSUPPORTED, PACKET_SOCKS5_CONNECTION_REFUSED,
    PACKET_SOCKS5_CONNECT_FAIL, PACKET_SOCKS5_HOST_UNREACHABLE, PACKET_SOCKS5_NETWORK_UNREACHABLE,
    PACKET_SOCKS5_RULESET_DENIED, PACKET_SOCKS5_TTL_EXPIRED, PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
};

use std::net::{Ipv4Addr, Ipv6Addr};

// Wire constants, straight from the Go `socks_manager.go` const block. Kept
// private: nothing outside this module needs to speak raw SOCKS bytes.
const SOCKS4_VERSION: u8 = 0x04;
const SOCKS5_VERSION: u8 = 0x05;

const SOCKS4_CMD_CONNECT: u8 = 0x01;
const SOCKS4_REPLY_GRANTED: u8 = 0x5A;
const SOCKS4_REPLY_REJECTED: u8 = 0x5B;

const SOCKS5_AUTH_METHOD_NO_AUTH: u8 = 0x00;
const SOCKS5_AUTH_METHOD_USER_PASS: u8 = 0x02;
const SOCKS5_AUTH_METHOD_NO_ACCEPTABLE: u8 = 0xFF;

const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;

const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;

// SOCKS5 reply codes (the second byte of a reply), from the Go const block.
// `SUCCESS` and the failure codes are what the local app sees as the result of
// its CONNECT; the mapping from our internal failure packet types to these is
// [`socks_reply_for_packet_type`].
const SOCKS5_REPLY_SUCCESS: u8 = 0x00;
const SOCKS5_REPLY_GENERAL_FAILURE: u8 = 0x01;
const SOCKS5_REPLY_RULESET_DENIED: u8 = 0x02;
const SOCKS5_REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
const SOCKS5_REPLY_HOST_UNREACHABLE: u8 = 0x04;
const SOCKS5_REPLY_CONNECTION_REFUSED: u8 = 0x05;
const SOCKS5_REPLY_TTL_EXPIRED: u8 = 0x06;
const SOCKS5_REPLY_CMD_NOT_SUPPORTED: u8 = 0x07;
const SOCKS5_REPLY_ATYP_NOT_SUPPORTED: u8 = 0x08;

const SOCKS5_USER_AUTH_VERSION: u8 = 0x01;
const SOCKS5_USER_AUTH_SUCCESS: u8 = 0x00;
const SOCKS5_USER_AUTH_FAILURE: u8 = 0x01;

/// The most non-null bytes a null-terminated SOCKS4 field (user id, SOCKS4a
/// host) may hold before it is rejected as too long. Matches the Go
/// `readNullTerminatedSocksField` cap exactly.
const SOCKS_FIELD_MAX: usize = 255;

/// The listener's auth posture, taken from the client config. `user`/`pass` are
/// raw bytes because the SOCKS comparison is byte-wise (Go compares the decoded
/// field against the configured string without any normalisation).
#[derive(Debug, Clone, Default)]
pub struct SocksConfig {
    /// Whether username/password auth is required. When false, SOCKS5 offers
    /// "no auth" and SOCKS4 is accepted outright.
    pub auth_required: bool,
    /// The expected username (raw bytes).
    pub user: Vec<u8>,
    /// The expected password (raw bytes).
    pub pass: Vec<u8>,
}

impl SocksConfig {
    /// Whether SOCKS4/4a is accepted at all. Mirrors the Go `supportsSOCKS4`:
    /// always when auth is off, and when auth is on only in the degenerate
    /// "username set, password empty" case (SOCKS4 has no password field, so a
    /// username-only credential can still be checked).
    pub fn supports_socks4(&self) -> bool {
        !self.auth_required || (!self.user.is_empty() && self.pass.is_empty())
    }
}

/// One thing the handshake wants the caller to do, emitted in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksAction {
    /// Write these bytes back to the SOCKS client.
    Write(Vec<u8>),
    /// A username/password (or SOCKS4 user id) check just failed. The caller
    /// records it against the client IP for brute-force rate limiting. Always
    /// followed by a `Write` of the failure reply and then `Close`.
    AuthFailed,
    /// A username/password check just succeeded. The caller clears any recorded
    /// failures for the client IP.
    AuthSucceeded,
    /// The client asked to CONNECT to `target`. The caller allocates a stream,
    /// remembers `socks_version` (so it can format the eventual reply), and
    /// fires the stream-setup packets. The connection stays open.
    Connect { target: Target, socks_version: u8 },
    /// The client asked for a UDP ASSOCIATE (the DNS-over-SOCKS path). `target`
    /// is the address field from the request. The connection stays open.
    UdpAssociate { target: Target },
    /// The handshake failed; close the connection. Any `Write` emitted just
    /// before this carries the error reply to flush first.
    Close,
}

/// The parser's position in the handshake. Only small `Copy` data (byte
/// lengths) rides in the variants; the parsed command, address type, host and
/// port live on the struct so this stays `Copy` and cheap to read out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Waiting for the single version byte that picks SOCKS4 vs SOCKS5.
    Version,
    /// SOCKS5: the method-count byte.
    S5NMethods,
    /// SOCKS5: `n` method bytes.
    S5Methods(usize),
    /// SOCKS5 user/pass: the 2-byte auth header (version + username length).
    S5AuthHeader,
    /// SOCKS5 user/pass: `n` username bytes.
    S5AuthUser(usize),
    /// SOCKS5 user/pass: the 1-byte password length.
    S5AuthPassLen,
    /// SOCKS5 user/pass: `n` password bytes.
    S5AuthPass(usize),
    /// SOCKS5: the 4-byte request header (version, command, reserved, atyp).
    S5ReqHeader,
    /// SOCKS5: a 4-byte IPv4 address.
    S5AddrIpv4,
    /// SOCKS5: the 1-byte domain length.
    S5AddrDomainLen,
    /// SOCKS5: `n` domain bytes.
    S5AddrDomain(usize),
    /// SOCKS5: a 16-byte IPv6 address.
    S5AddrIpv6,
    /// SOCKS5: the 2-byte port, after which the request is complete.
    S5Port,
    /// SOCKS4: the 7-byte fixed request (command, port, IPv4).
    S4Request,
    /// SOCKS4: the null-terminated user id.
    S4UserId,
    /// SOCKS4a: the null-terminated host, read only for the `0.0.0.x` form.
    S4Domain,
    /// Handshake finished successfully (a `Connect`/`UdpAssociate` was emitted).
    Done,
    /// Handshake finished in failure (a `Close` was emitted).
    Failed,
}

/// Result of a single `step`, telling the drive loop whether to keep going.
enum Step {
    /// Progress was made; loop again.
    Continue,
    /// Not enough bytes buffered yet; wait for more input.
    NeedMore,
    /// Terminal; stop the loop.
    Stop,
}

/// The local SOCKS handshake state machine for one client connection.
///
/// Feed it bytes with [`push`](Self::push); it returns the actions to carry
/// out. It is single-use: once it emits a `Connect`/`UdpAssociate` or a
/// `Close`, [`is_finished`](Self::is_finished) is true and further input is
/// ignored (any trailing bytes are available via
/// [`take_remaining`](Self::take_remaining)).
#[derive(Debug, Clone)]
pub struct SocksHandshake {
    cfg: SocksConfig,
    state: State,
    /// Unconsumed input. `read` is how far into it the parser has advanced; the
    /// slice `buf[read..]` is what is still to be parsed.
    buf: Vec<u8>,
    read: usize,
    // Fields captured mid-parse and used a step or two later.
    cmd: u8,
    atyp: u8,
    host: String,
    port: u16,
    socks4_ip: [u8; 4],
    auth_user: Vec<u8>,
}

impl SocksHandshake {
    /// Start a fresh handshake with the given auth config.
    pub fn new(cfg: SocksConfig) -> Self {
        Self {
            cfg,
            state: State::Version,
            buf: Vec::new(),
            read: 0,
            cmd: 0,
            atyp: 0,
            host: String::new(),
            port: 0,
            socks4_ip: [0; 4],
            auth_user: Vec::new(),
        }
    }

    /// Feed freshly read bytes and drive the handshake as far as it will go.
    /// Returns the actions to perform, in order. When the handshake is already
    /// finished this is a no-op returning an empty list.
    pub fn push(&mut self, data: &[u8]) -> Vec<SocksAction> {
        let mut out = Vec::new();
        if self.is_finished() {
            return out;
        }
        self.buf.extend_from_slice(data);
        while let Step::Continue = self.step(&mut out) {}
        self.compact();
        out
    }

    /// Whether the handshake has reached a terminal state.
    pub fn is_finished(&self) -> bool {
        matches!(self.state, State::Done | State::Failed)
    }

    /// Whether the handshake finished successfully (a target was produced).
    pub fn succeeded(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// Hand back any bytes that arrived after the handshake finished — the
    /// first bytes of the stream's own payload. Empties the internal buffer.
    pub fn take_remaining(&mut self) -> Vec<u8> {
        let rest = self.buf.split_off(self.read);
        self.buf.clear();
        self.read = 0;
        rest
    }

    /// Drop already-consumed bytes from the front of the buffer so it does not
    /// grow without bound across many `push` calls mid-handshake.
    fn compact(&mut self) {
        if self.read > 0 {
            self.buf.drain(..self.read);
            self.read = 0;
        }
    }

    /// Bytes still waiting to be parsed.
    fn remaining(&self) -> usize {
        self.buf.len() - self.read
    }

    /// Borrow the next `n` unconsumed bytes without advancing, if present.
    fn peek(&self, n: usize) -> Option<&[u8]> {
        if self.remaining() >= n {
            Some(&self.buf[self.read..self.read + n])
        } else {
            None
        }
    }

    /// One parse step for the current state. Reads from `buf[read..]`, advances
    /// `read`, pushes any actions, and transitions `state`.
    fn step(&mut self, out: &mut Vec<SocksAction>) -> Step {
        match self.state {
            State::Version => self.step_version(out),
            State::S5NMethods => self.step_s5_nmethods(),
            State::S5Methods(n) => self.step_s5_methods(n, out),
            State::S5AuthHeader => self.step_s5_auth_header(out),
            State::S5AuthUser(n) => self.step_s5_auth_user(n),
            State::S5AuthPassLen => self.step_s5_auth_pass_len(),
            State::S5AuthPass(n) => self.step_s5_auth_pass(n, out),
            State::S5ReqHeader => self.step_s5_req_header(out),
            State::S5AddrIpv4 => self.step_s5_addr_ipv4(),
            State::S5AddrDomainLen => self.step_s5_addr_domain_len(),
            State::S5AddrDomain(n) => self.step_s5_addr_domain(n),
            State::S5AddrIpv6 => self.step_s5_addr_ipv6(),
            State::S5Port => self.step_s5_port(out),
            State::S4Request => self.step_s4_request(out),
            State::S4UserId => self.step_s4_user_id(out),
            State::S4Domain => self.step_s4_domain(out),
            State::Done | State::Failed => Step::Stop,
        }
    }

    /// Mark the handshake failed and ask the caller to close.
    fn fail_close(&mut self, out: &mut Vec<SocksAction>) -> Step {
        out.push(SocksAction::Close);
        self.state = State::Failed;
        Step::Stop
    }

    fn step_version(&mut self, out: &mut Vec<SocksAction>) -> Step {
        let v = match self.peek(1) {
            Some(b) => b[0],
            None => return Step::NeedMore,
        };
        self.read += 1;
        match v {
            SOCKS5_VERSION => {
                self.state = State::S5NMethods;
                Step::Continue
            }
            SOCKS4_VERSION => {
                if self.cfg.supports_socks4() {
                    self.state = State::S4Request;
                    Step::Continue
                } else {
                    self.fail_close(out)
                }
            }
            _ => self.fail_close(out),
        }
    }

    fn step_s5_nmethods(&mut self) -> Step {
        let n = match self.peek(1) {
            Some(b) => b[0] as usize,
            None => return Step::NeedMore,
        };
        self.read += 1;
        self.state = State::S5Methods(n);
        Step::Continue
    }

    fn step_s5_methods(&mut self, n: usize, out: &mut Vec<SocksAction>) -> Step {
        let methods = match self.peek(n) {
            Some(m) => m,
            None => return Step::NeedMore,
        };
        // Pick the method the Go server would: user/pass when auth is on and the
        // client offered it, no-auth when auth is off and the client offered it,
        // otherwise "no acceptable methods".
        let selected = if self.cfg.auth_required {
            if methods.contains(&SOCKS5_AUTH_METHOD_USER_PASS) {
                SOCKS5_AUTH_METHOD_USER_PASS
            } else {
                SOCKS5_AUTH_METHOD_NO_ACCEPTABLE
            }
        } else if methods.contains(&SOCKS5_AUTH_METHOD_NO_AUTH) {
            SOCKS5_AUTH_METHOD_NO_AUTH
        } else {
            SOCKS5_AUTH_METHOD_NO_ACCEPTABLE
        };
        self.read += n;
        out.push(SocksAction::Write(vec![SOCKS5_VERSION, selected]));
        match selected {
            SOCKS5_AUTH_METHOD_NO_ACCEPTABLE => self.fail_close(out),
            SOCKS5_AUTH_METHOD_USER_PASS => {
                self.state = State::S5AuthHeader;
                Step::Continue
            }
            _ => {
                self.state = State::S5ReqHeader;
                Step::Continue
            }
        }
    }

    fn step_s5_auth_header(&mut self, out: &mut Vec<SocksAction>) -> Step {
        let hdr = match self.peek(2) {
            Some(h) => h,
            None => return Step::NeedMore,
        };
        let auth_ver = hdr[0];
        let user_len = hdr[1] as usize;
        self.read += 2;
        if auth_ver != SOCKS5_USER_AUTH_VERSION {
            return self.fail_close(out);
        }
        self.state = State::S5AuthUser(user_len);
        Step::Continue
    }

    fn step_s5_auth_user(&mut self, n: usize) -> Step {
        let user = match self.peek(n) {
            Some(u) => u,
            None => return Step::NeedMore,
        };
        self.auth_user = user.to_vec();
        self.read += n;
        self.state = State::S5AuthPassLen;
        Step::Continue
    }

    fn step_s5_auth_pass_len(&mut self) -> Step {
        let n = match self.peek(1) {
            Some(b) => b[0] as usize,
            None => return Step::NeedMore,
        };
        self.read += 1;
        self.state = State::S5AuthPass(n);
        Step::Continue
    }

    fn step_s5_auth_pass(&mut self, n: usize, out: &mut Vec<SocksAction>) -> Step {
        let pass = match self.peek(n) {
            Some(p) => p,
            None => return Step::NeedMore,
        };
        let ok = self.auth_user == self.cfg.user && pass == self.cfg.pass.as_slice();
        self.read += n;
        if !ok {
            // Go order: write the failure reply, then record the failure, then
            // close.
            out.push(SocksAction::Write(vec![
                SOCKS5_USER_AUTH_VERSION,
                SOCKS5_USER_AUTH_FAILURE,
            ]));
            out.push(SocksAction::AuthFailed);
            return self.fail_close(out);
        }
        // Go order: record the success, then write the success reply.
        out.push(SocksAction::AuthSucceeded);
        out.push(SocksAction::Write(vec![
            SOCKS5_USER_AUTH_VERSION,
            SOCKS5_USER_AUTH_SUCCESS,
        ]));
        self.state = State::S5ReqHeader;
        Step::Continue
    }

    fn step_s5_req_header(&mut self, out: &mut Vec<SocksAction>) -> Step {
        let hdr = match self.peek(4) {
            Some(h) => h,
            None => return Step::NeedMore,
        };
        let ver = hdr[0];
        let cmd = hdr[1];
        let rsv = hdr[2];
        let atyp = hdr[3];
        self.read += 4;
        if ver != SOCKS5_VERSION || rsv != 0x00 {
            return self.fail_close(out);
        }
        self.cmd = cmd;
        self.atyp = atyp;
        match atyp {
            SOCKS5_ATYP_IPV4 => {
                self.state = State::S5AddrIpv4;
                Step::Continue
            }
            SOCKS5_ATYP_DOMAIN => {
                self.state = State::S5AddrDomainLen;
                Step::Continue
            }
            SOCKS5_ATYP_IPV6 => {
                self.state = State::S5AddrIpv6;
                Step::Continue
            }
            // Unknown address type: Go closes with no reply.
            _ => self.fail_close(out),
        }
    }

    fn step_s5_addr_ipv4(&mut self) -> Step {
        let ip = match self.peek(4) {
            Some(b) => [b[0], b[1], b[2], b[3]],
            None => return Step::NeedMore,
        };
        self.host = Ipv4Addr::from(ip).to_string();
        self.read += 4;
        self.state = State::S5Port;
        Step::Continue
    }

    fn step_s5_addr_domain_len(&mut self) -> Step {
        let n = match self.peek(1) {
            Some(b) => b[0] as usize,
            None => return Step::NeedMore,
        };
        self.read += 1;
        self.state = State::S5AddrDomain(n);
        Step::Continue
    }

    fn step_s5_addr_domain(&mut self, n: usize) -> Step {
        let domain = match self.peek(n) {
            Some(d) => d,
            None => return Step::NeedMore,
        };
        // Real SOCKS clients send ASCII/IDNA hostnames, so this is exact; a
        // non-UTF-8 name (which no browser sends) would be lossily converted.
        self.host = String::from_utf8_lossy(domain).into_owned();
        self.read += n;
        self.state = State::S5Port;
        Step::Continue
    }

    fn step_s5_addr_ipv6(&mut self) -> Step {
        let ip: [u8; 16] = match self.peek(16) {
            Some(b) => b.try_into().expect("peeked exactly 16 bytes"),
            None => return Step::NeedMore,
        };
        self.host = Ipv6Addr::from(ip).to_string();
        self.read += 16;
        self.state = State::S5Port;
        Step::Continue
    }

    fn step_s5_port(&mut self, out: &mut Vec<SocksAction>) -> Step {
        let port = match self.peek(2) {
            Some(b) => u16::from_be_bytes([b[0], b[1]]),
            None => return Step::NeedMore,
        };
        self.read += 2;
        self.port = port;
        let target = Target {
            address_type: wire_atyp_to_address_type(self.atyp),
            host: std::mem::take(&mut self.host),
            port,
        };
        match self.cmd {
            SOCKS5_CMD_CONNECT => {
                out.push(SocksAction::Connect {
                    target,
                    socks_version: SOCKS5_VERSION,
                });
                self.state = State::Done;
                Step::Stop
            }
            SOCKS5_CMD_UDP_ASSOCIATE => {
                out.push(SocksAction::UdpAssociate { target });
                self.state = State::Done;
                Step::Stop
            }
            _ => {
                out.push(SocksAction::Write(socks5_reply_cmd_unsupported()));
                self.fail_close(out)
            }
        }
    }

    fn step_s4_request(&mut self, out: &mut Vec<SocksAction>) -> Step {
        let req = match self.peek(7) {
            Some(r) => r,
            None => return Step::NeedMore,
        };
        let cmd = req[0];
        let port = u16::from_be_bytes([req[1], req[2]]);
        let ip = [req[3], req[4], req[5], req[6]];
        self.read += 7;
        if cmd != SOCKS4_CMD_CONNECT {
            out.push(SocksAction::Write(socks4_reply(false)));
            return self.fail_close(out);
        }
        self.cmd = cmd;
        self.port = port;
        self.socks4_ip = ip;
        self.state = State::S4UserId;
        Step::Continue
    }

    fn step_s4_user_id(&mut self, out: &mut Vec<SocksAction>) -> Step {
        let user = match self.read_null_terminated() {
            FieldScan::Found(bytes) => bytes,
            FieldScan::NeedMore => return Step::NeedMore,
            FieldScan::TooLong => return self.fail_close(out),
        };
        // Auth check (SOCKS4 has only a user id, no password).
        if self.cfg.auth_required && user != self.cfg.user {
            out.push(SocksAction::AuthFailed);
            out.push(SocksAction::Write(socks4_reply(false)));
            return self.fail_close(out);
        }
        if self.cfg.auth_required {
            out.push(SocksAction::AuthSucceeded);
        }
        // SOCKS4a signals "resolve this hostname" by sending 0.0.0.x (x != 0)
        // as the IP and appending the real hostname after the user id.
        let ip = self.socks4_ip;
        if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
            self.state = State::S4Domain;
            return Step::Continue;
        }
        let target = Target {
            address_type: ADDRESS_TYPE_IPV4,
            host: Ipv4Addr::from(ip).to_string(),
            port: self.port,
        };
        out.push(SocksAction::Connect {
            target,
            socks_version: SOCKS4_VERSION,
        });
        self.state = State::Done;
        Step::Stop
    }

    fn step_s4_domain(&mut self, out: &mut Vec<SocksAction>) -> Step {
        let domain = match self.read_null_terminated() {
            FieldScan::Found(bytes) => bytes,
            FieldScan::NeedMore => return Step::NeedMore,
            FieldScan::TooLong => return self.fail_close(out),
        };
        if domain.is_empty() {
            out.push(SocksAction::Write(socks4_reply(false)));
            return self.fail_close(out);
        }
        let target = Target {
            address_type: ADDRESS_TYPE_DOMAIN,
            host: String::from_utf8_lossy(&domain).into_owned(),
            port: self.port,
        };
        out.push(SocksAction::Connect {
            target,
            socks_version: SOCKS4_VERSION,
        });
        self.state = State::Done;
        Step::Stop
    }

    /// Scan the unconsumed buffer for a null-terminated field, advancing past
    /// the terminator on success. Mirrors the Go `readNullTerminatedSocksField`
    /// length cap: a field may hold up to [`SOCKS_FIELD_MAX`] non-null bytes;
    /// the byte after that many non-null bytes, if still not a terminator, is a
    /// hard error.
    fn read_null_terminated(&mut self) -> FieldScan {
        let rest = &self.buf[self.read..];
        let limit = rest.len().min(SOCKS_FIELD_MAX + 1);
        if let Some(k) = rest[..limit].iter().position(|&b| b == 0x00) {
            let field = rest[..k].to_vec();
            self.read += k + 1;
            FieldScan::Found(field)
        } else if rest.len() > SOCKS_FIELD_MAX {
            // More than 255 non-null bytes with no terminator in sight.
            FieldScan::TooLong
        } else {
            FieldScan::NeedMore
        }
    }
}

/// Outcome of scanning for a null-terminated field.
enum FieldScan {
    /// Terminator found; here are the bytes before it.
    Found(Vec<u8>),
    /// No terminator yet and the field is still within the length cap.
    NeedMore,
    /// The field ran past the length cap without a terminator.
    TooLong,
}

/// Map a SOCKS5 address-type byte to the tunnel's target address-type byte.
/// They share the same values, but spelling the mapping out keeps the two
/// vocabularies from silently coupling.
fn wire_atyp_to_address_type(atyp: u8) -> u8 {
    match atyp {
        SOCKS5_ATYP_IPV4 => ADDRESS_TYPE_IPV4,
        SOCKS5_ATYP_DOMAIN => ADDRESS_TYPE_DOMAIN,
        SOCKS5_ATYP_IPV6 => ADDRESS_TYPE_IPV6,
        other => other,
    }
}

/// The SOCKS5 "command not supported" reply, bound to `0.0.0.0:0` exactly as
/// the Go `sendSocksReply(_, 0x07, IPV4, IPv4zero, 0)` builds it.
fn socks5_reply_cmd_unsupported() -> Vec<u8> {
    socks5_connect_reply(SOCKS5_REPLY_CMD_NOT_SUPPORTED)
}

/// The 8-byte SOCKS4 reply, granted or rejected, matching the Go
/// `sendSocks4Reply`. Used both to reject a SOCKS4 handshake and to carry the
/// eventual CONNECT result back to a SOCKS4 client.
pub fn socks4_reply(success: bool) -> Vec<u8> {
    let code = if success {
        SOCKS4_REPLY_GRANTED
    } else {
        SOCKS4_REPLY_REJECTED
    };
    vec![0x00, code, 0, 0, 0, 0, 0, 0]
}

/// The 10-byte SOCKS5 CONNECT-result reply with the given reply code, bound to
/// `0.0.0.0:0`. This is the exact form the Go `writeSocksConnectResultLocked`
/// sends for a SOCKS5 client (`sendSocksReply(_, rep, IPV4, IPv4zero, 0)`),
/// whether the result is success ([`SOCKS5_REPLY_SUCCESS`]) or a failure code
/// from [`socks_reply_for_packet_type`].
pub fn socks5_connect_reply(rep: u8) -> Vec<u8> {
    vec![
        SOCKS5_VERSION,
        rep,
        0x00,
        SOCKS5_ATYP_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
}

/// Map one of our internal `SOCKS5_*` failure packet types to the SOCKS5 reply
/// code the local app should see. Mirrors the Go `socksReplyForPacketType`:
/// each specific failure maps to its matching reply, and the auth/upstream/
/// generic-connect failures (and anything unrecognised) fold to a general
/// failure. The returned code goes into [`socks5_connect_reply`] (or, for a
/// SOCKS4 client, only its success/failure distinction is used).
pub fn socks_reply_for_packet_type(packet_type: u8) -> u8 {
    match packet_type {
        PACKET_SOCKS5_RULESET_DENIED => SOCKS5_REPLY_RULESET_DENIED,
        PACKET_SOCKS5_NETWORK_UNREACHABLE => SOCKS5_REPLY_NETWORK_UNREACHABLE,
        PACKET_SOCKS5_HOST_UNREACHABLE => SOCKS5_REPLY_HOST_UNREACHABLE,
        PACKET_SOCKS5_CONNECTION_REFUSED => SOCKS5_REPLY_CONNECTION_REFUSED,
        PACKET_SOCKS5_TTL_EXPIRED => SOCKS5_REPLY_TTL_EXPIRED,
        PACKET_SOCKS5_COMMAND_UNSUPPORTED => SOCKS5_REPLY_CMD_NOT_SUPPORTED,
        PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED => SOCKS5_REPLY_ATYP_NOT_SUPPORTED,
        PACKET_SOCKS5_AUTH_FAILED
        | PACKET_SOCKS5_UPSTREAM_UNAVAILABLE
        | PACKET_SOCKS5_CONNECT_FAIL => SOCKS5_REPLY_GENERAL_FAILURE,
        _ => SOCKS5_REPLY_GENERAL_FAILURE,
    }
}

/// The SOCKS5 reply code for a successful CONNECT, exposed so the stream
/// manager can pass it to [`socks5_connect_reply`] without reaching for the
/// private wire constant.
pub const SOCKS5_SUCCESS: u8 = SOCKS5_REPLY_SUCCESS;
