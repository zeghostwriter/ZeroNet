//! The Windows packet device, on top of Wintun.
//!
//! Windows has no TUN device of its own. Every VPN on the platform ships or
//! requires a driver, and the one with a stable, documented user-space API is
//! WireGuard's Wintun. This module drives it.
//!
//! **The driver is not bundled.** `wintun.dll` is loaded by name at run time
//! and nothing here links against it, so a build of Zray carries no driver, no
//! signing requirement and no installer. An operator who has not installed it
//! gets an error that says so, rather than a mysterious failure to route.
//!
//! ## Why threads rather than an async handle
//!
//! Wintun hands out a Win32 event to wait on, and tokio has no equivalent of
//! `AsyncFd` for Windows event objects. Registering one would mean an IOCP
//! shim for a handle that is not an IOCP-capable object. So the read side runs
//! on a dedicated thread that blocks on the event and forwards packets through
//! a bounded channel; the write side needs no thread at all, because sending
//! is a memcpy into a shared ring and Wintun documents it as thread-safe.
//!
//! The bound on that channel is deliberate: it is a network device, and a
//! reader that cannot keep up should drop packets the way a congested link
//! does, not grow a queue until the process dies.

#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::io;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;

/// How many packets may be buffered between the reader thread and the async
/// side before the oldest are dropped.
const READ_QUEUE: usize = 512;

/// Wintun's ring capacity, in bytes. The driver requires a power of two
/// between 128 KiB and 64 MiB; 4 MiB is WireGuard's own default and holds a
/// burst comfortably without reserving much.
const RING_CAPACITY: u32 = 4 * 1024 * 1024;

/// What Zray calls itself in the adapter's "tunnel type" field, which is what
/// Windows shows in the network connections list.
const TUNNEL_TYPE: &str = "Zray";

const ERROR_NO_MORE_ITEMS: u32 = 259;

/// How long the reader blocks on Wintun's event before re-checking the stop
/// flag. A bounded wait rather than `INFINITE`, so shutdown never depends on
/// the driver signalling one last time.
const READ_WAIT_MS: u32 = 250;

type Handle = *mut c_void;
type Module = *mut c_void;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryW(name: *const u16) -> Module;
    fn FreeLibrary(module: Module) -> i32;
    fn GetProcAddress(module: Module, name: *const u8) -> *const c_void;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn GetLastError() -> u32;
}

/// The subset of `wintun.h` this adapter uses.
///
/// Resolved by name at load time. A DLL that is present but too old to export
/// one of these is rejected up front, rather than crashing at the first packet.
struct Api {
    module: Module,
    create_adapter: unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> Handle,
    open_adapter: unsafe extern "system" fn(*const u16) -> Handle,
    close_adapter: unsafe extern "system" fn(Handle),
    start_session: unsafe extern "system" fn(Handle, u32) -> Handle,
    end_session: unsafe extern "system" fn(Handle),
    get_read_wait_event: unsafe extern "system" fn(Handle) -> Handle,
    receive_packet: unsafe extern "system" fn(Handle, *mut u32) -> *mut u8,
    release_receive_packet: unsafe extern "system" fn(Handle, *const u8),
    allocate_send_packet: unsafe extern "system" fn(Handle, u32) -> *mut u8,
    send_packet: unsafe extern "system" fn(Handle, *const u8),
}

// The module handle and the function pointers are immutable once resolved, and
// Wintun documents its session functions as safe to call from any thread.
unsafe impl Send for Api {}
unsafe impl Sync for Api {}

impl Api {
    fn load() -> io::Result<Self> {
        let name = wide("wintun.dll");
        // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives the
        // call.
        let module = unsafe { LoadLibraryW(name.as_ptr()) };
        if module.is_null() {
            return Err(io::Error::other(format!(
                "wintun.dll could not be loaded (error {}). Zray does not \
                 bundle a TUN driver: install Wintun from wintun.net and place \
                 wintun.dll beside the executable or on the library search path.",
                unsafe { GetLastError() }
            )));
        }

        // SAFETY: each symbol is looked up in the module just loaded, and the
        // signatures match `wintun.h` for the exported name.
        let resolved = unsafe {
            (|| {
                Ok::<_, io::Error>(Self {
                    module,
                    create_adapter: std::mem::transmute(symbol(module, b"WintunCreateAdapter\0")?),
                    open_adapter: std::mem::transmute(symbol(module, b"WintunOpenAdapter\0")?),
                    close_adapter: std::mem::transmute(symbol(module, b"WintunCloseAdapter\0")?),
                    start_session: std::mem::transmute(symbol(module, b"WintunStartSession\0")?),
                    end_session: std::mem::transmute(symbol(module, b"WintunEndSession\0")?),
                    get_read_wait_event: std::mem::transmute(symbol(
                        module,
                        b"WintunGetReadWaitEvent\0",
                    )?),
                    receive_packet: std::mem::transmute(symbol(module, b"WintunReceivePacket\0")?),
                    release_receive_packet: std::mem::transmute(symbol(
                        module,
                        b"WintunReleaseReceivePacket\0",
                    )?),
                    allocate_send_packet: std::mem::transmute(symbol(
                        module,
                        b"WintunAllocateSendPacket\0",
                    )?),
                    send_packet: std::mem::transmute(symbol(module, b"WintunSendPacket\0")?),
                })
            })()
        };
        match resolved {
            Ok(api) => Ok(api),
            Err(error) => {
                // SAFETY: the module was loaded above and no pointer into it
                // escaped, because construction failed.
                unsafe { FreeLibrary(module) };
                Err(error)
            }
        }
    }
}

impl Drop for Api {
    fn drop(&mut self) {
        // SAFETY: the module was loaded by `load` and every handle derived
        // from it has already been closed by `Session::drop`, which owns an
        // `Arc<Api>` and therefore runs first.
        unsafe { FreeLibrary(self.module) };
    }
}

/// SAFETY: `module` must be a live module handle and `name` a NUL-terminated
/// symbol name.
unsafe fn symbol(module: Module, name: &[u8]) -> io::Result<*const c_void> {
    let address = unsafe { GetProcAddress(module, name.as_ptr()) };
    if address.is_null() {
        let symbol = String::from_utf8_lossy(&name[..name.len() - 1]).into_owned();
        return Err(io::Error::other(format!(
            "wintun.dll does not export {symbol}; the installed driver is too \
             old for this build"
        )));
    }
    Ok(address)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The adapter and session handles, owned jointly by both halves.
///
/// Reading needs `&mut` (it drains a channel) while writing does not, so the
/// two are separate values — but the handles underneath must be closed exactly
/// once, and only after both halves and the reader thread are done with them.
/// That is what this is for.
struct Owned {
    api: Arc<Api>,
    adapter: Handle,
    session: Handle,
    stop: Arc<AtomicBool>,
}

// SAFETY: Wintun documents its session functions as callable from any thread,
// and these handles are immutable for the lifetime of this value.
unsafe impl Send for Owned {}
unsafe impl Sync for Owned {}

impl Drop for Owned {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Ending the session also signals the read event, so the reader thread
        // wakes, observes the stop flag and exits.
        // SAFETY: both handles were produced by `Session::open` and this runs
        // once, when the last holder of the `Arc` goes away.
        unsafe {
            (self.api.end_session)(self.session);
            (self.api.close_adapter)(self.adapter);
        }
    }
}

/// The send half. Cheap to clone and safe to share.
pub(crate) struct SessionWriter {
    owned: Arc<Owned>,
}

impl SessionWriter {
    /// Send one packet into the adapter's ring.
    pub(crate) fn send(&self, packet: &[u8]) -> io::Result<usize> {
        let length: u32 = packet.len().try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "packet exceeds a u32 length")
        })?;
        // SAFETY: the session is live for as long as `owned`, and the returned
        // pointer is valid for exactly `length` bytes until `send_packet`
        // hands it back to the driver.
        let slot = unsafe { (self.owned.api.allocate_send_packet)(self.owned.session, length) };
        if slot.is_null() {
            // The ring is full. A network device drops here; queueing would
            // trade a dropped packet for unbounded memory and added latency,
            // and the transport above already has to handle loss.
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "the Wintun send ring is full",
            ));
        }
        // SAFETY: `slot` points at `length` writable bytes obtained above.
        unsafe {
            ptr::copy_nonoverlapping(packet.as_ptr(), slot, packet.len());
            (self.owned.api.send_packet)(self.owned.session, slot);
        }
        Ok(packet.len())
    }
}

/// An open Wintun adapter and its packet session.
pub(crate) struct Session {
    owned: Arc<Owned>,
    packets: mpsc::Receiver<Vec<u8>>,
    /// Dropped packets, for the caller to report. A silently lossy device is
    /// indistinguishable from a censored one, which is the last confusion this
    /// project needs.
    dropped: Arc<std::sync::atomic::AtomicU64>,
}

impl Session {
    /// Create or reopen the named adapter and start passing packets.
    ///
    /// Creating an adapter needs administrator rights. Reopening an existing
    /// one is tried first so a restart does not churn the network stack — and
    /// so a service that was granted the right to create it once does not need
    /// it again.
    pub(crate) fn open(name: &str) -> io::Result<Self> {
        let api = Arc::new(Api::load()?);
        let wide_name = wide(name);
        let wide_type = wide(TUNNEL_TYPE);

        // SAFETY: both strings are NUL-terminated and outlive the calls.
        let adapter = unsafe {
            let existing = (api.open_adapter)(wide_name.as_ptr());
            if existing.is_null() {
                (api.create_adapter)(wide_name.as_ptr(), wide_type.as_ptr(), ptr::null())
            } else {
                existing
            }
        };
        if adapter.is_null() {
            let code = unsafe { GetLastError() };
            return Err(io::Error::other(format!(
                "Wintun could not create the adapter {name:?} (error {code}); \
                 creating a network adapter requires administrator rights"
            )));
        }

        // SAFETY: `adapter` is a live adapter handle.
        let session = unsafe { (api.start_session)(adapter, RING_CAPACITY) };
        if session.is_null() {
            let code = unsafe { GetLastError() };
            // SAFETY: the adapter was created above and is not otherwise owned.
            unsafe { (api.close_adapter)(adapter) };
            return Err(io::Error::other(format!(
                "Wintun could not start a session on {name:?} (error {code})"
            )));
        }

        let (sender, packets) = mpsc::channel(READ_QUEUE);
        let stop = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(std::sync::atomic::AtomicU64::new(0));

        let owned = Arc::new(Owned {
            api: Arc::clone(&api),
            adapter,
            session,
            stop: Arc::clone(&stop),
        });

        // On failure `owned` is dropped here, which ends the session and
        // closes the adapter again.
        spawn_reader(Arc::clone(&owned), sender, stop, Arc::clone(&dropped))?;

        Ok(Self {
            owned,
            packets,
            dropped,
        })
    }

    /// The send half, which needs no exclusive access.
    pub(crate) fn writer(&self) -> Arc<SessionWriter> {
        Arc::new(SessionWriter {
            owned: Arc::clone(&self.owned),
        })
    }

    /// Receive one packet. Returns its length, having copied it into `packet`.
    pub(crate) async fn recv(&mut self, packet: &mut [u8]) -> io::Result<usize> {
        let received = self.packets.recv().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the Wintun reader stopped; the adapter was removed or the \
                 driver was unloaded",
            )
        })?;
        if received.len() > packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet is larger than the supplied buffer",
            ));
        }
        packet[..received.len()].copy_from_slice(&received);
        Ok(received.len())
    }

    /// Packets discarded because the async side could not keep up.
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// The blocking half: wait on Wintun's event, drain the ring, forward.
fn spawn_reader(
    owned: Arc<Owned>,
    sender: mpsc::Sender<Vec<u8>>,
    stop: Arc<AtomicBool>,
    dropped: Arc<std::sync::atomic::AtomicU64>,
) -> io::Result<()> {
    // Holding the `Arc` is what keeps the handles alive for as long as this
    // thread might touch them: the session cannot be closed while the reader
    // is still inside `receive_packet`.
    std::thread::Builder::new()
        .name("zray-wintun-read".into())
        .spawn(move || {
            let api = &owned.api;
            let session = owned.session;
            // SAFETY: the session is live for the lifetime of this thread.
            let event = unsafe { (api.get_read_wait_event)(session) };
            // `stop` alone is not enough: it is set by `Owned::drop`, which
            // cannot run while this thread holds its `Arc<Owned>`. On an idle
            // adapter no packet ever arrives to discover the closed channel,
            // so the receiver going away is checked on every wake — otherwise
            // dropping the device would leak this thread, the session and the
            // adapter for the life of the process.
            while !stop.load(Ordering::Acquire) && !sender.is_closed() {
                let mut size: u32 = 0;
                // SAFETY: `size` is written by the driver; the returned
                // pointer is valid for `size` bytes until it is released.
                let packet = unsafe { (api.receive_packet)(session, &mut size) };
                if packet.is_null() {
                    let code = unsafe { GetLastError() };
                    if code == ERROR_NO_MORE_ITEMS {
                        // Nothing queued. Block until the driver says there is,
                        // with a bounded wait so the stop flag is still seen
                        // if the event is never signalled again.
                        // SAFETY: `event` belongs to the live session.
                        unsafe { WaitForSingleObject(event, READ_WAIT_MS) };
                        continue;
                    }
                    // The session is gone — the adapter was removed, or the
                    // driver unloaded. Either way there is nothing to read.
                    break;
                }

                // SAFETY: `packet` points at `size` readable bytes owned by
                // the driver until released immediately below.
                let copied = unsafe { std::slice::from_raw_parts(packet, size as usize) }.to_vec();
                // SAFETY: the pointer came from `receive_packet` and is
                // released exactly once.
                unsafe { (api.release_receive_packet)(session, packet) };

                match sender.try_send(copied) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
            }
        })
        .map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_strings_are_nul_terminated() {
        let encoded = wide("Zray");
        assert_eq!(encoded, vec![0x5a, 0x72, 0x61, 0x79, 0x00]);
    }

    #[test]
    fn the_ring_capacity_is_a_power_of_two_inside_wintuns_range() {
        // The driver rejects anything else, and it rejects it at session
        // start — long after the adapter has been created.
        assert!(RING_CAPACITY.is_power_of_two());
        assert!((128 * 1024..=64 * 1024 * 1024).contains(&RING_CAPACITY));
    }

    #[test]
    fn a_missing_driver_tells_the_operator_what_to_install() {
        // Only meaningful where wintun.dll is genuinely absent; where it is
        // present this asserts nothing and must not fail.
        if let Err(error) = Api::load() {
            let text = error.to_string();
            assert!(
                text.contains("wintun.dll") && text.contains("wintun.net"),
                "the error should name the driver and where to get it: {text}"
            );
        }
    }
}
