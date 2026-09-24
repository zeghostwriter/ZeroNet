/*
 * Zray — the C ABI for mobile host applications.
 *
 * Android and iOS own the tunnel; the proxy is a library inside the host's
 * VpnService or NEPacketTunnelProvider. Three things cross this boundary: the
 * TUN descriptor the platform created, a callback that exempts the proxy's own
 * sockets from that tunnel, and start/stop driven by the platform lifecycle.
 *
 * Threading: every function is safe to call from any thread.
 *
 * Strings: arguments are NUL-terminated UTF-8, borrowed for the call and never
 * retained. Returned strings are owned by the caller and must be released with
 * zray_string_free.
 *
 * Panics: every entry point contains its own faults. A failure inside the
 * library returns ZRAY_ERR_PANIC; it never aborts the host process.
 *
 * This header is maintained by hand and pinned to the Rust entry points by
 * crates/zray-mobile/tests/header_parity.rs, which fails if the two drift.
 */

#ifndef ZRAY_H
#define ZRAY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------- status */

/** Started, stopped, or configured successfully. */
#define ZRAY_OK 0
/** A pointer argument was null, or a string was not valid UTF-8. */
#define ZRAY_ERR_INVALID_ARGUMENT 1
/** The configuration was rejected. zray_last_error says why. */
#define ZRAY_ERR_CONFIG 2
/** Already running, or asked to stop while not running. */
#define ZRAY_ERR_STATE 3
/** Starting failed. zray_last_error says why. */
#define ZRAY_ERR_START 4
/** A hook could not be installed, because one already was. */
#define ZRAY_ERR_ALREADY_SET 5
/** A call panicked. The host process was not aborted. */
#define ZRAY_ERR_PANIC 6

/* ------------------------------------------------------------ diagnostics */

/**
 * The most recent failure, or NULL if the last call succeeded.
 * Release with zray_string_free.
 */
char *zray_last_error(void);

/** Release a string returned by this library. NULL is accepted. */
void zray_string_free(char *value);

/* ------------------------------------------------------ socket protection */

/**
 * Exempt one socket from the tunnel.
 *
 * Returns non-zero on success, matching VpnService.protect's boolean. A zero
 * return fails the connection that was being made, which is correct: an
 * unprotected socket does not work slowly, it routes back into the proxy.
 */
typedef int32_t (*zray_protect_callback)(int32_t fd, void *context);

/**
 * Install the host's socket-protection callback. Call before zray_start, at
 * most once per process. Pass NULL to leave sockets alone, which is normal on
 * iOS, where a packet-tunnel provider's own sockets are already exempt.
 */
int32_t zray_set_protect_callback(zray_protect_callback callback, void *context);

/* ----------------------------------------------------------- TUN handover */

/**
 * Hand the platform's TUN descriptor to the runtime.
 *
 * Ownership moves once zray_start succeeds: do not read, write or close the
 * descriptor after that. If zray_start fails, it is still yours to close.
 *
 * header_len is the platform's framing in front of each packet — 0 for
 * Android's VpnService, 4 for iOS's NEPacketTunnelProvider. mtu is the MTU the
 * host configured; the library cannot query it.
 */
int32_t zray_set_tun_descriptor(int32_t fd, int32_t header_len, int32_t mtu);

/* ------------------------------------------------------------- lifecycle */

/** Start the proxy with an Xray-shaped JSON configuration document. */
int32_t zray_start(const char *config_json);

/** Whether the proxy is running. */
int32_t zray_is_running(void);

/**
 * Replace the running configuration without dropping the tunnel. Sessions
 * already open finish on the configuration they started with. The inbound
 * listener topology cannot change this way (ZRAY_ERR_CONFIG); stop and start
 * for that. ZRAY_ERR_STATE if nothing is running.
 */
int32_t zray_reload(const char *config_json);

/**
 * The underlying network changed. Re-installs the current configuration as a
 * new generation, which drops the DNS cache and the resolver's pooled
 * connections. ZRAY_OK (and nothing done) when nothing is running.
 */
int32_t zray_network_changed(void);

/** Stop the proxy and release its runtime. */
int32_t zray_stop(void);

/** Traffic counters as JSON, or NULL if nothing is running. */
char *zray_stats_json(void);

#ifdef __cplusplus
}
#endif

#endif /* ZRAY_H */
