/*
 * Additive C API surface for i2p-proxy: exposes the destination/stream
 * primitives from libi2pd/api.h (i2p::api::CreateLocalDestination,
 * CreateStream, AcceptStream) as a flat C ABI, on top of the existing
 * capi.h init/start/stop lifecycle calls. Kept in a separate file from
 * capi.h/capi.cpp (upstream i2pd files) so upstream updates don't collide
 * with this addition.
 */
#ifndef CAPI2_H__
#define CAPI2_H__

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* i2pp_dest_t;
typedef void* i2pp_stream_t;

/* Sets i2pd's reseed/family certificate directory. Must be called after
 * I2PP_CreateDestination's caller has ensured certs exist on disk (or at
 * any point before the router starts reseeding); i2pd's own daemon main()
 * calls the equivalent of this (i2p::fs::SetCertsDir) itself, but our
 * embedding via libi2pd/api.h's InitI2P/StartI2P never does, so certsDir
 * stays empty and reseed silently can't find its trust roots otherwise. */
void I2PP_SetCertsDir(const char* dir);

/* Sets i2pd's own internal log verbosity (debug, info, warn, error, none).
 * Like SetCertsDir, this is normally applied in i2pd's daemon main()
 * (daemon/Daemon.cpp calls i2p::log::Logger().SetLogLevel(...) there) and
 * never in the libi2pd/api.h InitI2P/StartI2P path our embedding uses; the
 * --loglevel argv option is parsed into config but otherwise has no effect
 * without this call. */
void I2PP_SetLogLevel(const char* level);

/* Starts/stops UPnP automatic port forwarding (requests the router map our
 * NTCP2/SSU2 port). Requires the library to be built with USE_UPNP; a
 * no-op (with a log warning) otherwise. Intended for operators behind a
 * home/office router with UPnP enabled; does nothing for carrier-grade NAT
 * upstream of that router. Call once, after Start (so i2p::context already
 * knows our addresses/port) and before relying on inbound reachability. */
void I2PP_StartUPnP(void);
void I2PP_StopUPnP(void);

/* Load persistent destination keys from keysFile (created with random keys
 * on first use), and publish/create the local destination. Returns NULL on
 * failure. isPublic!=0 announces the destination's LeaseSet to the network
 * (required to accept inbound streams / act as an eepsite). */
i2pp_dest_t I2PP_CreateDestination(const char* keysFile, int isPublic);
void I2PP_DestroyDestination(i2pp_dest_t dest);

/* Writes the destination's base32 address (without the ".b32.i2p" suffix)
 * into out (must be at least 60 bytes). Returns the length written, or -1
 * if outLen is too small. */
int I2PP_GetBase32Address(i2pp_dest_t dest, char* out, int outLen);

/* Returns 1 once the destination has enough inbound/outbound tunnels built
 * to be usable, else 0. */
int I2PP_IsDestinationReady(i2pp_dest_t dest);

/* Resolves addr (a base32 string, with or without ".b32.i2p" suffix) and
 * opens a stream to it on the given port. timeoutMs bounds tunnel-build +
 * handshake time. Returns NULL on failure/timeout. */
i2pp_stream_t I2PP_Dial(i2pp_dest_t dest, const char* addr, uint16_t port, int timeoutMs);

/* Blocks until the next inbound stream arrives on dest, or returns NULL if
 * the destination is torn down while waiting (used to unblock on shutdown). */
i2pp_stream_t I2PP_Accept(i2pp_dest_t dest);

/* Writes the base32 address (no ".b32.i2p" suffix) of the stream's remote
 * peer into out (must be at least 60 bytes). Returns length written, or -1
 * on failure (e.g. an outbound stream whose remote identity isn't tracked
 * the same way, or a too-small buffer). */
int I2PP_StreamRemoteAddress(i2pp_stream_t s, char* out, int outLen);

long I2PP_StreamSend(i2pp_stream_t s, const uint8_t* buf, size_t len);
/* timeoutMs<=0 blocks indefinitely (until data, EOF, or stream close).
 * Returns -2 when a positive timeout expires while the stream remains open. */
long I2PP_StreamRecv(i2pp_stream_t s, uint8_t* buf, size_t len, int timeoutMs);
void I2PP_StreamClose(i2pp_stream_t s);

#ifdef __cplusplus
}
#endif

#endif
