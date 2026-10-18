#include "capi2.h"
#include "../libi2pd/api.h"
#include "../libi2pd/Identity.h"
#include "../libi2pd/Destination.h"
#include "../libi2pd/Streaming.h"
#include "../libi2pd/Base.h"
#include "../libi2pd/FS.h"
#include "../libi2pd/Log.h"
#include "../daemon/UPnP.h"

#include <cstring>
#include <fstream>
#include <vector>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <thread>
#include <memory>

namespace {

// Wraps a ClientDestination together with the queue that its persistent
// AcceptStreams() callback (invoked on i2pd's own io_service thread) feeds,
// so I2PP_Accept can block synchronously from a cgo-called OS thread.
struct DestHandle
{
	std::shared_ptr<i2p::client::ClientDestination> dest;

	std::mutex m;
	std::condition_variable cv;
	std::deque<std::shared_ptr<i2p::stream::Stream>> pending;
	bool closed = false;
};

bool ParseBase32 (const char* addr, i2p::data::IdentHash& hash)
{
	std::string s (addr);
	const std::string suffix = ".b32.i2p";
	if (s.size() > suffix.size() && s.compare (s.size() - suffix.size(), suffix.size(), suffix) == 0)
		s.resize (s.size() - suffix.size());
	if (s.size() != 52) return false; // 32 bytes base32-encoded, no padding
	return hash.FromBase32 (s) == i2p::data::IdentHash::len;
}

} // namespace

extern "C" {

void I2PP_SetCertsDir (const char* dir)
{
	i2p::fs::SetCertsDir (dir);
}

void I2PP_SetLogLevel (const char* level)
{
	i2p::log::Logger ().SetLogLevel (level);
}

namespace {
	std::unique_ptr<i2p::transport::UPnP> g_UPnP;
}

void I2PP_StartUPnP ()
{
	if (!g_UPnP)
		g_UPnP.reset (new i2p::transport::UPnP ());
	g_UPnP->Start ();
}

void I2PP_StopUPnP ()
{
	if (g_UPnP)
		g_UPnP->Stop ();
}

i2pp_dest_t I2PP_CreateDestination (const char* keysFile, int isPublic)
{
	i2p::data::PrivateKeys keys;
	bool loaded = false;

	std::ifstream f (keysFile, std::ifstream::binary);
	if (f)
	{
		std::vector<uint8_t> buf ((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
		if (!buf.empty() && keys.FromBuffer (buf.data(), buf.size()) > 0)
			loaded = true;
	}
	if (!loaded)
	{
		keys = i2p::data::PrivateKeys::CreateRandomKeys (
			i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519,
			i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD, true);

		std::vector<uint8_t> buf (keys.GetFullLen ());
		size_t len = keys.ToBuffer (buf.data(), buf.size());
		std::ofstream out (keysFile, std::ofstream::binary | std::ofstream::trunc);
		if (!out) return nullptr;
		out.write (reinterpret_cast<const char*>(buf.data()), len);
		if (!out) return nullptr;
	}

	auto localDest = i2p::api::CreateLocalDestination (keys, isPublic != 0);
	if (!localDest) return nullptr;

	auto h = new DestHandle ();
	h->dest = localDest;

	// Keep a raw pointer alive inside the lambda's closure; DestroyDestination
	// marks h->closed and wakes any blocked Accept before the ClientDestination
	// itself is torn down, so this callback never fires on a dangling handle.
	i2p::api::AcceptStream (localDest, [h](std::shared_ptr<i2p::stream::Stream> stream)
	{
		std::lock_guard<std::mutex> lock (h->m);
		if (h->closed) { if (stream) stream->Close(); return; }
		h->pending.push_back (stream);
		h->cv.notify_one ();
	});

	return h;
}

void I2PP_DestroyDestination (i2pp_dest_t handle)
{
	if (!handle) return;
	auto h = static_cast<DestHandle*>(handle);
	{
		std::lock_guard<std::mutex> lock (h->m);
		h->closed = true;
		h->cv.notify_all ();
	}
	i2p::api::DestroyLocalDestination (h->dest);
	delete h;
}

int I2PP_GetBase32Address (i2pp_dest_t handle, char* out, int outLen)
{
	if (!handle) return -1;
	auto h = static_cast<DestHandle*>(handle);
	auto ident = h->dest->GetIdentHash ();
	std::string b32 = ident.ToBase32 ();
	if ((int)b32.size() >= outLen) return -1;
	std::memcpy (out, b32.data(), b32.size());
	out[b32.size()] = 0;
	return (int)b32.size();
}

int I2PP_IsDestinationReady (i2pp_dest_t handle)
{
	if (!handle) return 0;
	auto h = static_cast<DestHandle*>(handle);
	return h->dest->IsReady () ? 1 : 0;
}

i2pp_stream_t I2PP_Dial (i2pp_dest_t handle, const char* addr, uint16_t port, int timeoutMs)
{
	if (!handle) return nullptr;
	auto h = static_cast<DestHandle*>(handle);

	i2p::data::IdentHash hash;
	if (!ParseBase32 (addr, hash)) return nullptr;

	i2p::api::RequestLeaseSet (h->dest, hash);
	LogPrint (eLogInfo, "i2p-proxy: dialing destination ", hash.ToBase32 (), " port=", port, " timeoutMs=", timeoutMs);

	auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds (timeoutMs > 0 ? timeoutMs : 30000);
	// CreateStream only allocates/registers the stream. The initial SYN is
	// triggered by a zero-length Send (the same sequence used by i2pd's
	// libi2pd/api.cpp); without it, IsOpen never becomes true and repeatedly
	// creating streams just floods the destination with abandoned attempts.
	std::shared_ptr<i2p::stream::Stream> stream;
	while (std::chrono::steady_clock::now() < deadline)
	{
		stream = h->dest->CreateStream (hash, port);
		if (stream) break; // LeaseSet lookup completed; begin stream handshake.
		LogPrint (eLogInfo, "i2p-proxy: LeaseSet not available yet; retrying");
		std::this_thread::sleep_for (std::chrono::seconds (1));
	}
	if (!stream) {
		LogPrint (eLogWarning, "i2p-proxy: CreateStream timed out waiting for LeaseSet");
		return nullptr;
	}
	auto synResult = stream->Send (nullptr, 0);
	LogPrint (eLogInfo, "i2p-proxy: stream created, SYN send result=", synResult);
	while (!stream->IsEstablished () && std::chrono::steady_clock::now() < deadline)
		std::this_thread::sleep_for (std::chrono::milliseconds (200));
	if (!stream->IsEstablished ()) {
		LogPrint (eLogWarning, "i2p-proxy: stream did not open before deadline");
		stream->Close ();
		return nullptr;
	}
	LogPrint (eLogInfo, "i2p-proxy: stream established");

	auto out = new std::shared_ptr<i2p::stream::Stream> (stream);
	return out;
}

i2pp_stream_t I2PP_Accept (i2pp_dest_t handle)
{
	if (!handle) return nullptr;
	auto h = static_cast<DestHandle*>(handle);

	std::unique_lock<std::mutex> lock (h->m);
	h->cv.wait (lock, [h]{ return h->closed || !h->pending.empty (); });
	if (h->closed) return nullptr;

	auto stream = h->pending.front ();
	h->pending.pop_front ();
	return new std::shared_ptr<i2p::stream::Stream> (stream);
}

int I2PP_StreamRemoteAddress (i2pp_stream_t s, char* out, int outLen)
{
	if (!s) return -1;
	auto stream = *static_cast<std::shared_ptr<i2p::stream::Stream>*>(s);
	if (!stream) return -1;
	auto identity = stream->GetRemoteIdentity ();
	if (!identity) return -1;
	std::string b32 = identity->GetIdentHash ().ToBase32 ();
	if ((int)b32.size() >= outLen) return -1;
	std::memcpy (out, b32.data(), b32.size());
	out[b32.size()] = 0;
	return (int)b32.size();
}

long I2PP_StreamSend (i2pp_stream_t s, const uint8_t* buf, size_t len)
{
	if (!s) return -1;
	auto stream = *static_cast<std::shared_ptr<i2p::stream::Stream>*>(s);
	if (!stream || !stream->IsOpen ()) return -1;
	return (long) stream->Send (buf, len);
}

long I2PP_StreamRecv (i2pp_stream_t s, uint8_t* buf, size_t len, int timeoutMs)
{
	if (!s) return -1;
	auto stream = *static_cast<std::shared_ptr<i2p::stream::Stream>*>(s);
	if (!stream) return -1;
	// Stream::Receive's zero-second wait is an immediate poll (despite the
	// intuitive meaning of zero), so use a long timeout for the C API's
	// blocking mode and let stream close/EOF terminate it normally.
	int timeout = timeoutMs > 0 ? (timeoutMs + 999) / 1000 : 86400;
	size_t n = stream->Receive (buf, len, timeout);
	if (n == 0 && stream->IsOpen () && timeoutMs > 0) return -2; // timed out
	if (n == 0 && !stream->IsOpen ()) return 0; // EOF
	return (long) n;
}

void I2PP_StreamClose (i2pp_stream_t s)
{
	if (!s) return;
	auto ptr = static_cast<std::shared_ptr<i2p::stream::Stream>*>(s);
	if (*ptr) (*ptr)->Close ();
	delete ptr;
}

} // extern "C"
