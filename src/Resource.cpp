/*
 * Copyright (c) 2023 Chad Attermann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 */

#include "Resource.h"

#include "ResourceBuffer.h"
#include "ResourceData.h"
#include "Reticulum.h"
#include "Transport.h"
#include "Packet.h"
#include "Identity.h"
#include "Cryptography/Hashes.h"
#include "Log.h"

#include <MsgPack.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <string>

// Per-checkpoint heap trace through _build_outgoing. Investigation-only:
// each call formats a NOTICEF (a heap-allocated log line) on the hot
// outbound path, so it is compiled out unless RNS_VERBOSE_DIAG is defined
// by the firmware build. Define it to bring the [BO] timeline back.
#if defined(RNS_VERBOSE_DIAG) && (defined(ARDUINO_ARCH_ESP32) || defined(ESP32))
#include <esp_heap_caps.h>
#define BO_HEAP(label) do { \
    NOTICEF("[BO] %s dma_free=%u dma_largest=%u sram_free=%u sram_largest=%u", \
            (label), \
            (unsigned)heap_caps_get_free_size(MALLOC_CAP_DMA), \
            (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DMA), \
            (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), \
            (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL)); \
} while (0)
#else
#define BO_HEAP(label) do {} while (0)
#endif

using namespace RNS;
using namespace RNS::Type::Resource;
using namespace RNS::Utilities;

// --------------------------------------------------------------------------
// Minimal msgpack codec, scoped to ResourceAdvertisement.
//
// The upstream MsgPack library's high-level from_map() API requires a fixed
// key/value layout at compile time, which doesn't fit the q-field's
// nil-or-bin polymorphism. Rather than fight that, we hand-roll the subset
// of msgpack we need (fixmap/map16, fixstr/str8, fixint/uint8/uint16/uint32,
// bin8/bin16/bin32, nil). ~120 LOC, no template heroics, easy to audit
// against the msgpack spec.
// --------------------------------------------------------------------------
namespace {

class MpReader {
public:
	MpReader(const uint8_t* data, size_t size) : _p(data), _end(data + size) {}

	bool ok() const { return !_err && _p <= _end; }
	bool eof() const { return _p >= _end; }

	bool read_map_size(size_t& out) {
		if (eof()) { _err = true; return false; }
		uint8_t b = *_p++;
		if ((b & 0xf0) == 0x80) { out = b & 0x0f; return true; }    // fixmap
		if (b == 0xde) {                                            // map16
			if (_end - _p < 2) { _err = true; return false; }
			out = (uint16_t(_p[0]) << 8) | _p[1]; _p += 2; return true;
		}
		if (b == 0xdf) {                                            // map32
			if (_end - _p < 4) { _err = true; return false; }
			out = (uint32_t(_p[0]) << 24) | (uint32_t(_p[1]) << 16) |
			      (uint32_t(_p[2]) << 8) | _p[3];
			_p += 4; return true;
		}
		_err = true; return false;
	}

	bool read_str(std::string& out) {
		if (eof()) { _err = true; return false; }
		uint8_t b = *_p++;
		size_t len = 0;
		if ((b & 0xe0) == 0xa0) { len = b & 0x1f; }                 // fixstr
		else if (b == 0xd9) {                                       // str8
			if (eof()) { _err = true; return false; }
			len = *_p++;
		}
		else if (b == 0xda) {                                       // str16
			if (_end - _p < 2) { _err = true; return false; }
			len = (uint16_t(_p[0]) << 8) | _p[1]; _p += 2;
		}
		else { _err = true; return false; }
		if ((size_t)(_end - _p) < len) { _err = true; return false; }
		out.assign((const char*)_p, len);
		_p += len; return true;
	}

	bool read_uint(uint32_t& out) {
		if (eof()) { _err = true; return false; }
		uint8_t b = *_p++;
		if ((b & 0x80) == 0x00) { out = b; return true; }           // positive fixint
		if (b == 0xcc) {                                            // uint8
			if (eof()) { _err = true; return false; }
			out = *_p++; return true;
		}
		if (b == 0xcd) {                                            // uint16
			if (_end - _p < 2) { _err = true; return false; }
			out = (uint16_t(_p[0]) << 8) | _p[1]; _p += 2; return true;
		}
		if (b == 0xce) {                                            // uint32
			if (_end - _p < 4) { _err = true; return false; }
			out = (uint32_t(_p[0]) << 24) | (uint32_t(_p[1]) << 16) |
			      (uint32_t(_p[2]) << 8) | _p[3];
			_p += 4; return true;
		}
		_err = true; return false;
	}

	// Read bin (or accept nil and yield an empty Bytes).
	bool read_bin_or_nil(Bytes& out) {
		if (eof()) { _err = true; return false; }
		uint8_t b = *_p;
		if (b == 0xc0) { _p++; out = Bytes(); return true; }        // nil
		_p++;
		size_t len = 0;
		if (b == 0xc4) {                                            // bin8
			if (eof()) { _err = true; return false; }
			len = *_p++;
		}
		else if (b == 0xc5) {                                       // bin16
			if (_end - _p < 2) { _err = true; return false; }
			len = (uint16_t(_p[0]) << 8) | _p[1]; _p += 2;
		}
		else if (b == 0xc6) {                                       // bin32
			if (_end - _p < 4) { _err = true; return false; }
			len = (uint32_t(_p[0]) << 24) | (uint32_t(_p[1]) << 16) |
			      (uint32_t(_p[2]) << 8) | _p[3];
			_p += 4;
		}
		else { _err = true; return false; }
		if ((size_t)(_end - _p) < len) { _err = true; return false; }
		out = Bytes(_p, len);
		_p += len; return true;
	}

private:
	const uint8_t* _p;
	const uint8_t* _end;
	bool _err = false;
};

class MpWriter {
public:
	void write_map_size(size_t n) {
		if (n < 16) {
			_buf.push_back(uint8_t(0x80 | n));
		}
		else if (n <= 0xffff) {
			_buf.push_back(0xde);
			_buf.push_back(uint8_t((n >> 8) & 0xff));
			_buf.push_back(uint8_t(n & 0xff));
		}
		else {
			_buf.push_back(0xdf);
			_buf.push_back(uint8_t((n >> 24) & 0xff));
			_buf.push_back(uint8_t((n >> 16) & 0xff));
			_buf.push_back(uint8_t((n >> 8)  & 0xff));
			_buf.push_back(uint8_t(n & 0xff));
		}
	}
	void write_str(const char* s) {
		const size_t len = strlen(s);
		if (len < 32) {
			_buf.push_back(uint8_t(0xa0 | len));
		}
		else if (len <= 0xff) {
			_buf.push_back(0xd9);
			_buf.push_back(uint8_t(len));
		}
		else {
			_buf.push_back(0xda);
			_buf.push_back(uint8_t((len >> 8) & 0xff));
			_buf.push_back(uint8_t(len & 0xff));
		}
		_buf.insert(_buf.end(), (const uint8_t*)s, (const uint8_t*)s + len);
	}
	void write_uint(uint32_t v) {
		if (v <= 0x7f)       { _buf.push_back(uint8_t(v)); }
		else if (v <= 0xff)  { _buf.push_back(0xcc); _buf.push_back(uint8_t(v)); }
		else if (v <= 0xffff){
			_buf.push_back(0xcd);
			_buf.push_back(uint8_t((v >> 8) & 0xff));
			_buf.push_back(uint8_t(v & 0xff));
		}
		else {
			_buf.push_back(0xce);
			_buf.push_back(uint8_t((v >> 24) & 0xff));
			_buf.push_back(uint8_t((v >> 16) & 0xff));
			_buf.push_back(uint8_t((v >> 8)  & 0xff));
			_buf.push_back(uint8_t(v & 0xff));
		}
	}
	void write_bin(const uint8_t* p, size_t n) {
		if (n <= 0xff)        { _buf.push_back(0xc4); _buf.push_back(uint8_t(n)); }
		else if (n <= 0xffff) {
			_buf.push_back(0xc5);
			_buf.push_back(uint8_t((n >> 8) & 0xff));
			_buf.push_back(uint8_t(n & 0xff));
		}
		else {
			_buf.push_back(0xc6);
			_buf.push_back(uint8_t((n >> 24) & 0xff));
			_buf.push_back(uint8_t((n >> 16) & 0xff));
			_buf.push_back(uint8_t((n >> 8)  & 0xff));
			_buf.push_back(uint8_t(n & 0xff));
		}
		_buf.insert(_buf.end(), p, p + n);
	}
	void write_nil() { _buf.push_back(0xc0); }

	Bytes finalize() const { return Bytes(_buf.data(), _buf.size()); }

private:
	std::vector<uint8_t> _buf;
};

}  // anonymous namespace


// --------------------------------------------------------------------------
// ResourceAdvertisement::pack / unpack
// --------------------------------------------------------------------------

Bytes RNS::ResourceAdvertisement::pack() const {
	MpWriter w;
	w.write_map_size(11);

	w.write_str("t"); w.write_uint(_t);
	w.write_str("d"); w.write_uint(_d);
	w.write_str("n"); w.write_uint(_n);
	w.write_str("h"); w.write_bin(_h.data(), _h.size());
	w.write_str("r"); w.write_bin(_r.data(), _r.size());
	w.write_str("o"); w.write_bin(_o.data(), _o.size());
	w.write_str("i"); w.write_uint(_i);
	w.write_str("l"); w.write_uint(_l);
	w.write_str("q");
	if (_q.empty()) w.write_nil();
	else            w.write_bin(_q.data(), _q.size());
	w.write_str("f"); w.write_uint(_f);
	w.write_str("m"); w.write_bin(_m.data(), _m.size());

	return w.finalize();
}

bool RNS::ResourceAdvertisement::unpack(const Bytes& body) {
	MpReader r(body.data(), body.size());
	size_t n_entries = 0;
	if (!r.read_map_size(n_entries)) {
		WARNING("ResourceAdvertisement::unpack: bad map header");
		return false;
	}

	bool got_t = false, got_d = false, got_n = false, got_h = false,
	     got_r = false, got_o = false, got_i = false, got_l = false,
	     got_q = false, got_f = false, got_m = false;

	for (size_t i = 0; i < n_entries; ++i) {
		std::string key;
		if (!r.read_str(key)) {
			WARNING("ResourceAdvertisement::unpack: bad key");
			return false;
		}
		if      (key == "t") { uint32_t v; if (!r.read_uint(v)) return false; _t = v; got_t = true; }
		else if (key == "d") { uint32_t v; if (!r.read_uint(v)) return false; _d = v; got_d = true; }
		else if (key == "n") { uint32_t v; if (!r.read_uint(v)) return false; _n = uint16_t(v); got_n = true; }
		else if (key == "h") { if (!r.read_bin_or_nil(_h)) return false; got_h = true; }
		else if (key == "r") { if (!r.read_bin_or_nil(_r)) return false; got_r = true; }
		else if (key == "o") { if (!r.read_bin_or_nil(_o)) return false; got_o = true; }
		else if (key == "i") { uint32_t v; if (!r.read_uint(v)) return false; _i = v; got_i = true; }
		else if (key == "l") { uint32_t v; if (!r.read_uint(v)) return false; _l = v; got_l = true; }
		else if (key == "q") { if (!r.read_bin_or_nil(_q)) return false; got_q = true; }
		else if (key == "f") { uint32_t v; if (!r.read_uint(v)) return false; _f = uint8_t(v); got_f = true; }
		else if (key == "m") { if (!r.read_bin_or_nil(_m)) return false; got_m = true; }
		else {
			// Unknown key — skip the value generously by trying types in turn.
			Bytes _skip_bin; uint32_t _skip_int;
			if (!r.read_bin_or_nil(_skip_bin)) {
				if (!r.read_uint(_skip_int)) {
					WARNINGF("ResourceAdvertisement::unpack: unknown key '%s' with unparseable value", key.c_str());
					return false;
				}
			}
		}
	}

	if (!(got_t && got_d && got_n && got_h && got_r && got_o &&
	      got_i && got_l && got_q && got_f && got_m)) {
		WARNING("ResourceAdvertisement::unpack: missing required key(s)");
		return false;
	}
	return true;
}

//Resource::Resource(const Link& link /*= {Type::NONE}*/) :
//	_object(new ResourceData(link))
//{
//	assert(_object);
//	MEM("Resource object created");
//}

Resource::Resource(const Bytes& data, const Link& link, const Bytes& request_id, bool is_response, double timeout) :
	_object(new ResourceData(link))
{
	assert(_object);
	MEM("Resource object created");
	// Request/response-framed resource (used by Link::request); the actual
	// pack-and-send work happens later in the sender pipeline. We just stash
	// the inputs for now.
	_object->_initiator   = true;
	_object->_is_request  = !is_response;
	_object->_is_response = is_response;
	_object->_request_id  = request_id;
	_object->_encrypted   = data;       // placeholder; the sender pipeline encrypts via Link
	_object->_timeout     = timeout;
	_object->_status      = Type::Resource::NONE;
	_object->_last_activity_ms = Utilities::OS::ltime();
}

Resource::Resource(const Bytes& data, const Link& link, bool advertise /*= true*/, bool auto_compress /*= true*/, Callbacks::concluded callback /*= nullptr*/, Callbacks::progress progress_callback /*= nullptr*/, double timeout /*= 0.0*/, int segment_index /*= 1*/, const Bytes& original_hash /*= {Type::NONE}*/, const Bytes& request_id /*= {Type::NONE}*/, bool is_response /*= false*/) :
	_object(new ResourceData(link))
{
	assert(_object);
	MEM("Resource object created");
	_object->_initiator         = true;
	_object->_callbacks._concluded = callback;
	_object->_callbacks._progress  = progress_callback;
	_object->_encrypted         = data;     // _build_outgoing replaces this with the ciphertext
	_object->_segment_index     = (uint32_t)segment_index;
	_object->_total_segments    = 1;
	_object->_is_split          = false;
	_object->_original_hash     = (original_hash.size() > 0 ? original_hash : Bytes());
	_object->_request_id        = request_id;
	_object->_is_request        = !is_response && !request_id.empty();
	_object->_is_response       = is_response;
	_object->_compressed        = false;    // never set; plan declines bz2
	_object->_has_metadata      = false;
	_object->_encrypted_flag    = true;     // Resource always encrypts via Link
	_object->_timeout           = timeout;
	_object->_status            = Type::Resource::NONE;
	_object->_last_activity_ms  = Utilities::OS::ltime();

	//p if not hasattr(data, "read") and self.metadata_size + len(data) > Resource.MAX_EFFICIENT_SIZE:
	//p     ... data = tempfile.TemporaryFile(); data.write(original_data) ...
	//p self.total_segments = ((self.total_size-1)//Resource.MAX_EFFICIENT_SIZE)+1
	// (Resource.py:271-312) Data larger than MAX_EFFICIENT_SIZE is spilled
	// to an input file under the resource-tmp dir and transferred as
	// consecutive segments; this constructor builds segment 1, and each
	// proven non-final segment chains the next via _advertise_next_segment.
	// Metadata is never sent by this port, so upstream's metadata_size is 0
	// and every non-final segment's slice is exactly MAX_EFFICIENT_SIZE.
	bool split_prep_failed = false;
	const size_t MES = Type::Resource::MAX_EFFICIENT_SIZE;
	if (data.size() > MES) {
		_object->_total_segments = (uint32_t)(((data.size() - 1) / MES) + 1);
		_object->_is_split       = true;
		//p self.total_size = data_size + self.metadata_size
		_object->_data_size      = (uint32_t)data.size();

		static uint64_t input_counter = 0;
		char path[256];
		snprintf(path, sizeof(path), "%s/snd_in_%llu_%llu.bin",
		         RNS::resource_tmp_path(),
		         (unsigned long long)Utilities::OS::ltime(),
		         (unsigned long long)(++input_counter));
		bool spill_ok = false;
		try {
			microStore::File f = Utilities::OS::open_file(
				path, microStore::File::ModeReadWrite);
			if (f) {
				// Chunked write with WDT resets — the input can be several
				// MiB and a single multi-MiB write could outlast the task
				// watchdog window on slow flash.
				size_t written = 0;
				const size_t CHUNK = 64 * 1024;
				while (written < data.size()) {
					const size_t n = std::min(CHUNK, data.size() - written);
					if (f.write(data.data() + written, n) != n) break;
					written += n;
					Utilities::OS::reset_watchdog();
				}
				f.flush();
				f.close();
				spill_ok = (written == data.size());
				if (!spill_ok) Utilities::OS::remove_file(path);
			}
		}
		catch (const std::exception& e) {
			ERRORF("Resource: input spill failed: %s", e.what());
		}
		if (spill_ok) {
			_object->_input_path = path;
			// Segment 1 covers [0, MAX_EFFICIENT_SIZE).
			_object->_encrypted = Bytes(data.data(), MES);
		}
		else {
			ERROR("Resource: could not spill split-transfer input; resource not advertised");
			split_prep_failed = true;
			_object->_status = Type::Resource::FAILED;
		}
	}

	if (advertise && !split_prep_failed) {
		const uint16_t link_mdu = const_cast<Link&>(link).get_mdu();
		if (_build_outgoing(link_mdu)) {
			_send_advertisement();
		}
		else {
			ERROR("Resource: _build_outgoing failed; resource not advertised");
		}
	}
}


// --------------------------------------------------------------------------
// Sender pipeline
//
// _build_outgoing prepares everything offline: encrypts the plaintext via
// the parent Link, generates the random_hash salt, computes the resource
// hash and expected proof, slices the ciphertext into parts of sdu bytes,
// computes a 4-byte map_hash per part, and concatenates all map_hashes
// into _map_full. After this method returns the resource is ready to be
// announced; no packets have been sent yet.
//
// _send_advertisement sends the RESOURCE_ADV (carrying the first
// HASHMAP_MAX_LEN map_hashes) plus follow-up RESOURCE_HMU packets for any
// additional hashmap segments, then transitions to ADVERTISED and
// registers with the Link's outgoing-resources set.
//
// The HMU send loop in _send_advertisement is proactive: rather than wait
// for the receiver to send REQ with exhausted=0xFF, we ship every HMU
// immediately after the ADV. The receiver's hashmap then fills in as the
// HMU packets arrive, and the receiver never has to ask for more. The
// reactive REQ-with-exhausted path stays implemented (step 8) for
// retry / out-of-order cases, but in the happy path the receiver gets
// the full hashmap up-front.
// --------------------------------------------------------------------------

bool Resource::_build_outgoing(uint16_t link_mdu) {
	assert(_object);
	auto& d = *_object;
	if (link_mdu == 0) {
		ERROR("Resource: link MDU is zero (link not active?)");
		return false;
	}

	BO_HEAP("enter");

	// Random salt prepended to the plaintext before encryption. Makes the
	// per-part map_hashes unpredictable to anyone without the Link key.
	Bytes random_hash = Identity::get_random_hash().left(Type::Resource::RANDOM_HASH_SIZE);
	d._random_hash = random_hash;

	const Bytes plaintext = d._encrypted;   // the constructor stashed plaintext here
	Bytes salted;
	salted.append(random_hash);
	salted.append(plaintext);

	BO_HEAP("pre-encrypt");

	// Encrypt via the Link's derived key (Fernet over AES-128-CBC).
	// AES on a 12 KB blob takes tens of ms; the per-part loop below
	// adds more. Same WDT story as the receive side.
	Utilities::OS::reset_watchdog();
	const Bytes encrypted = d._link.encrypt(salted);
	Utilities::OS::reset_watchdog();
	d._encrypted    = encrypted;
	d._transfer_size = (uint32_t)encrypted.size();
	//p self.d = resource.total_size  # Total uncompressed data size
	// (Resource.py:281,316,1263) `d` carries the FULL plaintext size of the
	// whole transfer — for split resources the constructor /
	// _advertise_next_segment preset it to the all-segments total; for
	// single-segment resources it is this segment's plaintext size.
	if (!d._is_split) d._data_size = (uint32_t)plaintext.size();

	BO_HEAP("post-encrypt");

	{
		// Sender-side mirror of the receiver's ADV gate: refuse to build a
		// transfer the peer-side firmware cap could never accept. For split
		// resources gate on the FULL data size, since that is what the
		// receiver's guard checks against its cap.
		const size_t firmware_cap = RNS::resource_max_incoming();
		const uint32_t gate_size = std::max(d._transfer_size, d._data_size);
		if (gate_size > firmware_cap) {
			ERRORF("Resource: transfer size %u exceeds firmware cap %u",
			       (unsigned)gate_size,
			       (unsigned)firmware_cap);
			return false;
		}
	}

	// Resource hash and the proof the receiver will return on completion.
	// Upstream RNS hashes the *plaintext* payload (Resource.py:441-443),
	// not the ciphertext, with the full 32-byte SHA-256 — and carries that
	// full hash on the wire everywhere (Identity.HASHLENGTH//8). Match it
	// byte-for-byte so real RNS peers (Sideband/MeshChat/NomadNet) can
	// verify the resources we send.
	d._hash           = Identity::full_hash(plaintext + random_hash);
	d._expected_proof = Identity::full_hash(plaintext + d._hash);
	if (d._original_hash.empty()) d._original_hash = d._hash;

	// Slice into parts. Each part's map_hash = sha256(part_data || random_hash)[:4].
	//
	// The resource SDU is NOT the link MDU. Upstream RNS (Resource.py:337-340)
	// slices resources at `mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE` when the link
	// MTU is known — resource parts are raw slices of the already-encrypted
	// stream sent with Packet context=RESOURCE (no per-packet re-encryption,
	// see Packet.cpp), so they can fill the packet up to the header, larger
	// than the AES-block-aligned `mdu` used for ordinary encrypted packets.
	// Using `get_mdu()` here made uR advertise more parts than an RNS receiver
	// recomputes from the same MTU, so RNS dropped the resource
	// ("Could not decode resource advertisement"). Match RNS exactly.
	const uint16_t link_mtu = const_cast<Link&>(d._link).mtu();
	const uint16_t sdu = link_mtu
		? (uint16_t)(link_mtu - Type::Reticulum::HEADER_MAXSIZE - Type::Reticulum::IFAC_MIN_SIZE)
		: link_mdu;
	d._sdu = sdu;
	const uint32_t n_parts32 = (d._transfer_size + sdu - 1) / sdu;
	if (n_parts32 > 0xFFFF) {
		ERRORF("Resource: too many parts: %u", (unsigned)n_parts32);
		return false;
	}
	const uint16_t n_parts = (uint16_t)n_parts32;
	d._parts_count = n_parts;
	// One bit per part for distinct-sent tracking (upstream's per-part
	// part.sent). Drives the AWAITING_PROOF transition in on_request.
	d._part_sent.assign(n_parts, false);
	d._distinct_sent = 0;

	d._parts.clear();
	// Only reserve _parts when we actually hold per-part bytes in memory
	// (non-spill path). Under spill_to_disk each part comes from
	// _load_part reading the spilled ciphertext file, so _parts stays
	// empty and the reserve would just waste internal-heap.
	d._map_full = Bytes();
	// Pre-size _map_full to its final size so the parts loop below can
	// memcpy each hash into place at offset i*MAPHASH_LEN instead of
	// appending. Avoids vector growth-realloc churn through the loop.
	uint8_t* map_full_dst = d._map_full.writable((size_t)n_parts * Type::Resource::MAPHASH_LEN);
	if (map_full_dst == nullptr) {
		ERROR("Resource: _map_full alloc failed");
		return false;
	}
	d._map_hashes_known.assign(n_parts, true);  // sender fills all slots itself

	// Spill decision: once the ciphertext is large enough that holding
	// it in PSRAM for the entire (potentially minutes-long) Resource
	// transfer is wasteful, write it to a temp file under the
	// resource-tmp directory and have _load_part read SDU-sized chunks
	// on demand. Threshold mirrors the receive side's HeapResourceBuffer
	// vs FlashResourceBuffer cutoff (RAM_BUFFER_THRESHOLD = 8 KiB), so a
	// fresh chat message stays in RAM and an attachment spills to disk.
	const bool spill_to_disk =
		d._transfer_size > Type::Resource::RAM_BUFFER_THRESHOLD;

	if (spill_to_disk) {
		// Pick a unique filename under the configured tmp dir. Resolver
		// is SD-aware in the firmware (set up in RNode_Firmware.ino).
		static uint64_t snd_counter = 0;
		char path[256];
		snprintf(path, sizeof(path), "%s/snd_%llu_%llu.bin",
		         RNS::resource_tmp_path(),
		         (unsigned long long)Utilities::OS::ltime(),
		         (unsigned long long)(++snd_counter));
		d._ciphertext_path = path;

		try {
			BO_HEAP("spill pre-open");
			microStore::File f = Utilities::OS::open_file(
				d._ciphertext_path.c_str(), microStore::File::ModeReadWrite);
			if (!f) {
				ERRORF("Resource: failed to open ciphertext temp '%s'",
				       d._ciphertext_path.c_str());
				d._ciphertext_path.clear();
				return false;
			}
			BO_HEAP("spill post-open");
			const size_t wrote = f.write(encrypted.data(), encrypted.size());
			BO_HEAP("spill post-write");
			f.flush();
			BO_HEAP("spill post-flush");
			f.close();
			BO_HEAP("spill post-close");
			if (wrote != encrypted.size()) {
				ERRORF("Resource: ciphertext write short %zu/%zu",
				       wrote, encrypted.size());
				Utilities::OS::remove_file(d._ciphertext_path.c_str());
				d._ciphertext_path.clear();
				return false;
			}
		}
		catch (const std::exception& e) {
			ERRORF("Resource: ciphertext spill failed: %s", e.what());
			d._ciphertext_path.clear();
			return false;
		}
		Utilities::OS::reset_watchdog();
	}

	if (!spill_to_disk) d._parts.reserve(n_parts);

	BO_HEAP("pre-parts-loop");

	for (uint16_t i = 0; i < n_parts; ++i) {
		const size_t offset = (size_t)i * sdu;
		const size_t length = std::min((size_t)sdu, (size_t)(d._transfer_size - offset));
		Bytes part_data(encrypted.data() + offset, length);

		const Bytes map_hash =
			Identity::full_hash(part_data + random_hash).left(Type::Resource::MAPHASH_LEN);

		// Only retain per-part bytes in memory when we're NOT spilling
		// — under spill, _load_part reads the chunk from disk on demand.
		if (!spill_to_disk) d._parts.push_back(part_data);

		// Write the 4-byte hash directly into _map_full at slot i. The
		// buffer was pre-sized via writable() above so the pointer is
		// stable for the whole loop.
		memcpy(map_full_dst + (size_t)i * Type::Resource::MAPHASH_LEN,
		       map_hash.data(), Type::Resource::MAPHASH_LEN);

		// SHA-256 per part + the vector growth. 30 iterations adds up
		// to a few hundred ms total — keep the WDT happy.
		if ((i & 0x07) == 0) Utilities::OS::reset_watchdog();
	}

	BO_HEAP("post-parts-loop");

	// Drop the in-memory ciphertext now that it's safely on disk; we
	// only need _hash + _expected_proof + _map_full from here on, and
	// the per-part bytes come from the file via _load_part.
	if (spill_to_disk) {
		d._encrypted = Bytes();
	}

	BO_HEAP("exit");
	return true;
}

bool Resource::_load_part(uint16_t index, Bytes& out) const {
	assert(_object);
	auto& d = *_object;
	if (index >= d._parts_count) return false;

	// In-memory path: trivial copy out of the pre-sliced vector.
	if (d._ciphertext_path.empty()) {
		if (index >= d._parts.size()) return false;
		out = d._parts[index];
		return true;
	}

	// Disk-backed path: open the spilled ciphertext, seek to the part
	// offset, read SDU-sized chunk. The final part may be short.
	const size_t offset = (size_t)index * (size_t)d._sdu;
	if (offset >= d._transfer_size) return false;
	const size_t length = std::min((size_t)d._sdu,
	                               (size_t)(d._transfer_size - offset));
	try {
		microStore::File f = Utilities::OS::open_file(
			d._ciphertext_path.c_str(), microStore::File::ModeRead);
		if (!f) {
			ERRORF("Resource::_load_part: open '%s' failed",
			       d._ciphertext_path.c_str());
			return false;
		}
		if (f.seek((uint32_t)offset, microStore::SeekModeSet) < 0) {
			ERRORF("Resource::_load_part: seek to %zu failed", offset);
			return false;
		}
		uint8_t* dst = out.writable(length);
		if (dst == nullptr) return false;
		const size_t got = f.read(dst, length);
		f.close();
		if (got != length) {
			ERRORF("Resource::_load_part: read short %zu/%zu", got, length);
			return false;
		}
		return true;
	}
	catch (const std::exception& e) {
		ERRORF("Resource::_load_part: %s", e.what());
		return false;
	}
}

void Resource::_release_ciphertext_file() {
	assert(_object);
	auto& d = *_object;
	if (d._ciphertext_path.empty()) return;
	try {
		if (Utilities::OS::file_exists(d._ciphertext_path.c_str())) {
			Utilities::OS::remove_file(d._ciphertext_path.c_str());
		}
	}
	catch (const std::exception& e) {
		WARNINGF("Resource: unlink '%s' threw: %s",
		         d._ciphertext_path.c_str(), e.what());
	}
	d._ciphertext_path.clear();
}

void Resource::_release_input_file() {
	assert(_object);
	auto& d = *_object;
	if (d._input_path.empty()) return;
	try {
		if (Utilities::OS::file_exists(d._input_path.c_str())) {
			Utilities::OS::remove_file(d._input_path.c_str());
		}
	}
	catch (const std::exception& e) {
		WARNINGF("Resource: unlink '%s' threw: %s",
		         d._input_path.c_str(), e.what());
	}
	d._input_path.clear();
}

void Resource::_release_segment_store() {
	assert(_object);
	auto& d = *_object;
	if (d._segment_store_path.empty()) return;
	try {
		if (Utilities::OS::file_exists(d._segment_store_path.c_str())) {
			Utilities::OS::remove_file(d._segment_store_path.c_str());
		}
	}
	catch (const std::exception& e) {
		WARNINGF("Resource: unlink '%s' threw: %s",
		         d._segment_store_path.c_str(), e.what());
	}
	d._segment_store_path.clear();
}

void Resource::_send_advertisement() {
	assert(_object);
	auto& d = *_object;

	const uint16_t HMU_MAX = Type::Resource::ResourceAdvertisement::HASHMAP_MAX_LEN;

	ResourceAdvertisement adv;
	adv.set_transfer_size(d._transfer_size);
	adv.set_data_size(d._data_size);
	adv.set_parts(d._parts_count);
	adv.set_hash(d._hash);
	adv.set_random_hash(d._random_hash);
	adv.set_original_hash(d._original_hash);
	adv.set_segment_index(d._segment_index);
	adv.set_total_segments(d._total_segments);
	adv.set_request_id(d._request_id);

	uint8_t flags = 0;
	if (d._encrypted_flag) flags |= ResourceAdvertisement::FLAG_ENCRYPTED;
	if (d._compressed)     flags |= ResourceAdvertisement::FLAG_COMPRESSED;
	if (d._is_split)       flags |= ResourceAdvertisement::FLAG_SPLIT;
	if (d._is_request)     flags |= ResourceAdvertisement::FLAG_IS_REQUEST;
	if (d._is_response)    flags |= ResourceAdvertisement::FLAG_IS_RESPONSE;
	if (d._has_metadata)   flags |= ResourceAdvertisement::FLAG_HAS_METADATA;
	adv.set_flags(flags);

	// ADV carries the first HMU_MAX map_hashes; follow-ups go via HMU.
	const size_t map_first_len =
		std::min((size_t)HMU_MAX * Type::Resource::MAPHASH_LEN, (size_t)d._map_full.size());
	adv.set_hashmap(Bytes(d._map_full.data(), map_first_len));

	const Bytes adv_body = adv.pack();
	try {
		Packet adv_packet(d._link, adv_body, Type::Packet::DATA, Type::Packet::RESOURCE_ADV);
		adv_packet.send();
	}
	catch (const std::exception& e) {
		ERRORF("Resource: ADV send failed: %s", e.what());
		d._status = Type::Resource::FAILED;
		// A resource that never got its ADV out won't reach any other
		// terminal path; drop its spill files here.
		_release_ciphertext_file();
		_release_input_file();
		return;
	}

	d._adv_sent_ms     = Utilities::OS::ltime();
	d._started_ms      = d._adv_sent_ms;
	d._last_activity_ms = d._adv_sent_ms;
	d._status          = Type::Resource::ADVERTISED;
	d._adv_retries_left = Type::Resource::MAX_ADV_RETRIES;

	DEBUGF("Resource: sent ADV n=%u t=%u hash=%s",
	       (unsigned)d._parts_count, (unsigned)d._transfer_size,
	       d._hash.toHex().c_str());

	// Proactively emit HMU packets for the rest of the hashmap.
	const uint16_t n_segments = (uint16_t)((d._parts_count + HMU_MAX - 1) / HMU_MAX);
	for (uint16_t seg = 1; seg < n_segments; ++seg) {
		_send_hmu((uint8_t)seg);
	}

	d._link.register_outgoing_resource(*this);
}

// --------------------------------------------------------------------------
// Receiver pipeline
//
// Resource::accept is the static factory the Link's RESOURCE_ADV dispatch
// arm calls. It constructs a Resource in receive mode, allocates a
// ResourceBuffer sized to the advertisement (Heap or Flash depending on
// _t against RAM_BUFFER_THRESHOLD), seeds the hashmap from the ADV's
// first-segment map_hashes (subsequent segments arrive via HMU), and
// transitions status to TRANSFERRING. The caller is responsible for
// calling link.register_incoming_resource(resource) and for invoking
// resource.send_part_request() to fire the first REQ.
// --------------------------------------------------------------------------

Resource Resource::accept(const ResourceAdvertisement& adv, const Link& link,
                          Callbacks::concluded concluded,
                          Callbacks::progress progress) {
	// Reuse the main constructor with advertise=false so no sender work
	// runs; then mutate fields into receive mode.
	Resource r(Bytes(), link, /*advertise=*/false, /*auto_compress=*/false,
	           concluded, progress, 0.0);

	auto& d = *r._object;
	d._initiator       = false;
	d._hash            = adv.hash();
	d._random_hash     = adv.random_hash();
	d._original_hash   = adv.original_hash();
	d._request_id      = adv.request_id();
	d._transfer_size   = adv.transfer_size();
	d._data_size       = adv.data_size();
	d._parts_count     = adv.parts();
	d._segment_index   = adv.segment_index();
	d._total_segments  = adv.total_segments();
	d._is_request      = adv.is_request();
	d._is_response     = adv.is_response();
	d._compressed      = adv.compressed();
	//p if adv.l > 1: resource.split = True
	//p else: resource.split = False
	// (Resource.py:202-203) Upstream derives split from the segment count,
	// not from the s flag.
	d._is_split        = (adv.total_segments() > 1);
	d._has_metadata    = adv.has_metadata();
	d._encrypted_flag  = adv.encrypted();
	// Resource SDU mirrors the sender's: mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE
	// when the link MTU is known (RNS Resource.py:337-340). Used here only for
	// transfer-timing (EIFR) estimates — the part count comes from adv.parts().
	{
		const uint16_t link_mtu = const_cast<Link&>(link).mtu();
		d._sdu = link_mtu
			? (uint16_t)(link_mtu - Type::Reticulum::HEADER_MAXSIZE - Type::Reticulum::IFAC_MIN_SIZE)
			: const_cast<Link&>(link).get_mdu();
	}

	//p previous_window = resource.link.get_last_resource_window()
	//p previous_eifr   = resource.link.get_last_resource_eifr()
	//p if previous_window: resource.window = previous_window
	//p if previous_eifr: resource.previous_eifr = previous_eifr
	// (Resource.py:214-219) Seed from the last concluded incoming resource
	// on this link — notably the previous segment of a split transfer — so
	// the window / rate don't restart from cold. previous_eifr lands
	// directly in _eifr_bps: update_eifr() only overwrites it once a real
	// observation exists, which is exactly when upstream stops consulting
	// its previous_eifr fallback.
	{
		const uint16_t previous_window = link.get_last_resource_window();
		const double   previous_eifr   = link.get_last_resource_eifr();
		if (previous_window > 0) d._window = previous_window;
		if (previous_eifr > 0.0) d._eifr_bps = previous_eifr;
	}

	//p resource.storagepath = RNS.Reticulum.resourcepath+"/"+resource.original_hash.hex()
	// Cross-segment accumulation file. Upstream ties the segments of a
	// split transfer together purely through this original_hash-keyed file
	// on disk — there is no other receiver-side cross-segment state
	// (Resource.py:197 sets the path, assemble() appends at 697-699, the
	// final segment reads it back and unlinks at 726-733).
	if (d._is_split) {
		char store[256];
		snprintf(store, sizeof(store), "%s/seg_%s.bin",
		         RNS::resource_tmp_path(),
		         d._original_hash.toHex().substr(0, 32).c_str());
		d._segment_store_path = store;
		if (d._segment_index <= 1) {
			// Fresh transfer: drop any stale leftover colliding on the
			// path (paranoia — original_hash is salted per transfer).
			try {
				if (Utilities::OS::file_exists(store)) Utilities::OS::remove_file(store);
			}
			catch (const std::exception&) {}
		}
		else {
			// Divergence from upstream, which appends blindly and leaves
			// orphaned files to a periodic cache cleaner the port doesn't
			// have: a continuation segment is only acceptable when the
			// store already holds exactly the previous segments' cleartext
			// — every non-final segment is exactly MAX_EFFICIENT_SIZE
			// bytes (metadata is never accepted). Anything else means a
			// missed segment (reboot, cleanup), so the assembled file
			// could only ever be garbage; refuse now instead of burning
			// minutes of airtime first. The FAILED status makes the
			// dispatch in Link::receive answer the ADV with RESOURCE_RCL.
			size_t store_size = 0;
			bool store_present = false;
			try {
				if (Utilities::OS::file_exists(store)) {
					microStore::File f = Utilities::OS::open_file(
						store, microStore::File::ModeRead);
					if (f) {
						store_size = f.size();
						store_present = true;
						f.close();
					}
				}
			}
			catch (const std::exception&) {}
			const size_t expected =
				(size_t)(d._segment_index - 1) * (size_t)Type::Resource::MAX_EFFICIENT_SIZE;
			if (!store_present || store_size != expected) {
				ERRORF("Resource::accept: continuation segment %u/%u but segment store holds %zu bytes (expected %zu); refusing",
				       (unsigned)d._segment_index, (unsigned)d._total_segments,
				       store_present ? store_size : (size_t)0, expected);
				d._status = Type::Resource::FAILED;
				return r;
			}
		}
	}

	// Allocate the receive buffer. Heap below RAM_BUFFER_THRESHOLD,
	// flash-streamed above. nullptr means flash quota would be exceeded.
	d._buffer = make_resource_buffer(d._transfer_size);
	if (!d._buffer || !d._buffer->open(d._transfer_size)) {
		ERRORF("Resource::accept: failed to allocate buffer for %u-byte resource",
		       (unsigned)d._transfer_size);
		d._status = Type::Resource::FAILED;
		return r;
	}

	// Pre-size _map_full to (parts_count * MAPHASH_LEN) zeros so receiver
	// slots can be filled by memcpy as ADV/HMU segments arrive. _map_hashes_known
	// tracks which slots are populated.
	uint8_t* map_full_dst = d._map_full.writable((size_t)d._parts_count * Type::Resource::MAPHASH_LEN);
	if (map_full_dst == nullptr) {
		ERROR("Resource::accept: _map_full alloc failed");
		d._status = Type::Resource::FAILED;
		return r;
	}
	d._map_hashes_known.assign(d._parts_count, false);
	const Bytes& adv_map = adv.hashmap();
	const size_t avail_hashes = adv_map.size() / Type::Resource::MAPHASH_LEN;
	for (size_t i = 0; i < avail_hashes && i < d._parts_count; ++i) {
		memcpy(map_full_dst + i * Type::Resource::MAPHASH_LEN,
		       adv_map.data() + i * Type::Resource::MAPHASH_LEN,
		       Type::Resource::MAPHASH_LEN);
		d._map_hashes_known[i] = true;
	}
	d._parts_received.assign(d._parts_count, false);
	d._received_count    = 0;
	d._outstanding_parts = 0;
	d._consecutive_completed_height = -1;

	d._status            = Type::Resource::TRANSFERRING;
	d._started_ms        = Utilities::OS::ltime();
	d._last_activity_ms  = d._started_ms;
	d._retries_left      = Type::Resource::MAX_RETRIES;

	DEBUGF("Resource::accept: n=%u t=%u hash=%s (buffer=%s)",
	       (unsigned)d._parts_count, (unsigned)d._transfer_size,
	       d._hash.toHex().c_str(),
	       d._buffer->is_flash_backed() ? "flash" : "heap");
	return r;
}

void Resource::send_part_request() {
	assert(_object);
	auto& d = *_object;
	if (d._status == Type::Resource::FAILED ||
	    d._status == Type::Resource::COMPLETE) return;

	// Find up to `window` not-yet-received parts starting from
	// consecutive_completed_height + 1 whose map_hashes we have.
	uint16_t pn = (d._consecutive_completed_height >= 0)
	                  ? (uint16_t)(d._consecutive_completed_height + 1) : 0;
	uint8_t exhausted = Type::Resource::HASHMAP_IS_NOT_EXHAUSTED;
	Bytes requested;
	uint16_t asked = 0;

	while (asked < d._window && pn < d._parts_count) {
		if (d._parts_received[pn]) { pn++; continue; }
		if (!d._map_hashes_known[pn]) {
			// Hashmap exhausted at this position — ask sender for more.
			exhausted = Type::Resource::HASHMAP_IS_EXHAUSTED;
			break;
		}
		requested.append(d._map_full.data() + (size_t)pn * Type::Resource::MAPHASH_LEN,
		                 Type::Resource::MAPHASH_LEN);
		asked++;
		pn++;
	}

	Bytes body;
	body.append(Bytes(&exhausted, 1));
	if (exhausted == Type::Resource::HASHMAP_IS_EXHAUSTED) {
		// Append the last known map_hash before the gap so the sender
		// can derive which segment to send next.
		uint16_t last_known = 0;
		for (uint16_t i = 0; i < d._parts_count; ++i) {
			if (d._map_hashes_known[i]) last_known = i;
		}
		body.append(d._map_full.data() + (size_t)last_known * Type::Resource::MAPHASH_LEN,
		            Type::Resource::MAPHASH_LEN);
	}
	body.append(d._hash);
	body.append(requested);

	try {
		Packet req_packet(d._link, body, Type::Packet::DATA, Type::Packet::RESOURCE_REQ);
		req_packet.send();
	}
	catch (const std::exception& e) {
		ERRORF("Resource: REQ send failed: %s", e.what());
		d._status = Type::Resource::FAILED;
		return;
	}
	d._req_sent_ms      = Utilities::OS::ltime();
	d._last_activity_ms = d._req_sent_ms;
	d._outstanding_parts = asked;
	// Snapshot the cumulative-bytes counter so the next on_part() that
	// completes the window can compute observed throughput as
	// (bytes_since_req / wall_time_since_req).
	d._rtt_rxd_bytes_at_part_req = d._rtt_rxd_bytes;
	DEBUGF("Resource: sent REQ (asking for %u parts, exhausted=%s)",
	       (unsigned)asked,
	       exhausted == Type::Resource::HASHMAP_IS_EXHAUSTED ? "yes" : "no");
}

// Receiver-only. Recompute EIFR from the last completed window's
// observation, or bootstrap from the underlying Link's
// establishment_cost / rtt when no window has completed yet.
//
// Floor at 50 bps so a degenerate observation (e.g. a single late
// part on a hostile link) doesn't pin the window timeout near
// infinity. Cap at 1 Mbps so an early observation on a fast probe
// doesn't shrink the window timeout below useful levels.
void Resource::update_eifr() {
	assert(_object);
	auto& d = *_object;
	double rtt_s = const_cast<Link&>(d._link).rtt();
	if (rtt_s <= 0.0) rtt_s = 2.0;

	// Observed-rate path: we have at least one completed window's worth
	// of (bytes, time) data. Trust it.
	if (d._req_sent_ms > 0 && d._rtt_rxd_bytes > d._rtt_rxd_bytes_at_part_req) {
		const uint64_t now_ms = Utilities::OS::ltime();
		const uint64_t window_ms = now_ms - d._req_sent_ms;
		const uint64_t delta_bytes = d._rtt_rxd_bytes - d._rtt_rxd_bytes_at_part_req;
		if (window_ms > 0) {
			d._eifr_bps = (double)(delta_bytes * 8ULL) * 1000.0 / (double)window_ms;
		}
	}

	// Bootstrap path: first window, no observation. Use link's
	// establishment cost / rtt as a rough rate estimate.
	if (d._eifr_bps <= 0.0) {
		const uint16_t est_cost = const_cast<Link&>(d._link).establishment_cost();
		if (est_cost > 0) {
			d._eifr_bps = (double)(est_cost * 8) / rtt_s;
		} else {
			// No establishment cost recorded — assume a pessimistic
			// 100 bps so first-window timeout is generous (typical
			// LoRa at SF7 BW250k is ~10 kbps so this errs on the
			// safe side of over-waiting).
			d._eifr_bps = 100.0;
		}
	}

	// Floor + ceiling so pathological samples don't break timeout math.
	if (d._eifr_bps < 50.0) d._eifr_bps = 50.0;
	if (d._eifr_bps > 1000000.0) d._eifr_bps = 1000000.0;
}

// --------------------------------------------------------------------------
// Receiver part assembly + PRF emission
// --------------------------------------------------------------------------

void Resource::on_part(const Packet& part_packet) {
	assert(_object);
	auto& d = *_object;
	if (d._status != Type::Resource::TRANSFERRING) return;
	if (!d._buffer) return;

	// Identify the part by recomputing the map_hash with our random salt.
	const Bytes& part_data = part_packet.data();
	const Bytes map_hash =
		Identity::full_hash(part_data + d._random_hash).left(Type::Resource::MAPHASH_LEN);

	// Match against not-yet-received slots whose map_hash we know.
	uint16_t matched = 0xFFFF;
	const uint8_t* candidate = map_hash.data();
	for (uint16_t i = 0; i < d._parts_count; ++i) {
		if (d._parts_received[i]) continue;
		if (!d._map_hashes_known[i]) continue;
		if (memcmp(d._map_full.data() + (size_t)i * Type::Resource::MAPHASH_LEN,
		           candidate, Type::Resource::MAPHASH_LEN) == 0) {
			matched = i;
			break;
		}
	}
	if (matched == 0xFFFF) {
		// Either a part for a different resource on the same link, or a
		// duplicate of one we've already accepted. Silently ignore — the
		// Python reference does the same.
		return;
	}

	if (!d._buffer->write_part(matched, d._sdu, part_data)) {
		ERRORF("Resource::on_part: buffer write failed for index %u", (unsigned)matched);
		d._status = Type::Resource::FAILED;
		return;
	}
	d._parts_received[matched] = true;
	d._received_count++;
	if (d._outstanding_parts > 0) d._outstanding_parts--;
	d._last_activity_ms = Utilities::OS::ltime();
	// Cumulative bytes seen — feeds update_eifr() on window completion
	// so the receiver's window_timeout adapts to airtime throttling.
	d._rtt_rxd_bytes += part_data.size();
	// Reset receiver retry budget on each successful part. The
	// retry counter only matters when the transfer stalls entirely; as
	// long as parts keep arriving we should keep going, even on a
	// lossy link where every batch needs another window_timeout to
	// re-request the dropped part.
	d._retries_left = Type::Resource::MAX_RETRIES;

	// Advance the consecutive-completed pointer as far as we can.
	int32_t cp = d._consecutive_completed_height + 1;
	while (cp < (int32_t)d._parts_count && d._parts_received[cp]) {
		d._consecutive_completed_height = cp;
		cp++;
	}

	// Fire progress callback (verified-bytes-so-far == received_count * sdu,
	// approximate but good enough for the SPA progress bar).
	if (d._callbacks._progress) {
		try { d._callbacks._progress(*this); }
		catch (const std::exception& e) {
			ERRORF("Resource::on_part: progress callback threw: %s", e.what());
		}
	}

	if (d._received_count >= d._parts_count) {
		_assemble_and_deliver();
	}
	else if (d._outstanding_parts == 0) {
		// Window fully satisfied: grow the sliding window and ramp window_max by
		// the measured rate, faithful to upstream RNS Resource.py:889-913.
		// Grow the window (+1) up to window_max, ratcheting window_min by the
		// flexibility so the min trails the window.
		if (d._window < d._window_max) {
			d._window += 1;
			if ((d._window - d._window_min) > (Type::Resource::WINDOW_FLEXIBILITY - 1)) {
				d._window_min += 1;
			}
		}
		// Measure the per-request data rate (bytes/sec) over the window that just
		// completed, then ramp window_max between the fast / very-slow tiers.
		if (d._req_sent_ms > 0) {
			const double rtt_s = (double)(Utilities::OS::ltime() - d._req_sent_ms) / 1000.0;
			const uint64_t req_transferred = (d._rtt_rxd_bytes > d._rtt_rxd_bytes_at_part_req)
				? (d._rtt_rxd_bytes - d._rtt_rxd_bytes_at_part_req) : 0;
			if (rtt_s > 0.0) {
				d._req_data_rtt_rate = (double)req_transferred / rtt_s;
				if (d._req_data_rtt_rate > (double)Type::Resource::RATE_FAST
						&& d._fast_rate_rounds < Type::Resource::FAST_RATE_THRESHOLD) {
					d._fast_rate_rounds += 1;
					if (d._fast_rate_rounds == Type::Resource::FAST_RATE_THRESHOLD) {
						d._window_max = Type::Resource::WINDOW_MAX_FAST;
					}
				}
				if (d._fast_rate_rounds == 0
						&& d._req_data_rtt_rate < (double)Type::Resource::RATE_VERY_SLOW
						&& d._very_slow_rate_rounds < Type::Resource::VERY_SLOW_RATE_THRESHOLD) {
					d._very_slow_rate_rounds += 1;
					if (d._very_slow_rate_rounds == Type::Resource::VERY_SLOW_RATE_THRESHOLD) {
						d._window_max = Type::Resource::WINDOW_MAX_VERY_SLOW;
					}
				}
			}
		}
		// Recompute EIFR from observed throughput before firing the next REQ so
		// future window timeouts reflect the link's real (airtime-throttled) rate.
		update_eifr();
		send_part_request();
	}
}

void Resource::on_hashmap_update(const Bytes& body) {
	assert(_object);
	auto& d = *_object;
	// Resource hash is the full 32-byte SHA-256 on the wire (RNS
	// Identity.HASHLENGTH//8), not the 16-byte truncated link/destination
	// hash.
	const uint8_t HASHLEN = Type::Identity::HASHLENGTH / 8;
	if (body.size() < HASHLEN + 3) {
		WARNING("RESOURCE_HMU body too short");
		return;
	}
	// Body: 32 B hash + msgpack([segment, hashmap_bytes])
	Bytes peer_hash(body.data(), HASHLEN);
	if (peer_hash != d._hash) {
		DEBUG("RESOURCE_HMU hash mismatch; ignoring");
		return;
	}
	MsgPack::Unpacker unpacker;
	unpacker.feed(body.data() + HASHLEN, body.size() - HASHLEN);
	uint32_t segment = 0;
	MsgPack::bin_t<uint8_t> hashmap_bytes;
	if (!unpacker.from_array(segment, hashmap_bytes)) {
		WARNING("RESOURCE_HMU msgpack unpack failed");
		return;
	}

	const uint16_t HMU_MAX = Type::Resource::ResourceAdvertisement::HASHMAP_MAX_LEN;
	const size_t seg_start_index = (size_t)segment * HMU_MAX;
	const size_t entries = hashmap_bytes.size() / Type::Resource::MAPHASH_LEN;
	uint8_t* map_full_dst = d._map_full.writable(d._map_full.size());
	for (size_t i = 0; i < entries; ++i) {
		const size_t slot = seg_start_index + i;
		if (slot >= d._parts_count) break;
		if (!d._map_hashes_known[slot]) {
			memcpy(map_full_dst + slot * Type::Resource::MAPHASH_LEN,
			       hashmap_bytes.data() + i * Type::Resource::MAPHASH_LEN,
			       Type::Resource::MAPHASH_LEN);
			d._map_hashes_known[slot] = true;
		}
	}
	DEBUGF("RESOURCE_HMU applied segment=%u (%u hashes)",
	       (unsigned)segment, (unsigned)entries);
}

void Resource::on_proof(const Bytes& proof) {
	assert(_object);
	auto& d = *_object;
	if (!d._initiator) return;
	if (d._status != Type::Resource::ADVERTISED &&
	    d._status != Type::Resource::TRANSFERRING &&
	    d._status != Type::Resource::AWAITING_PROOF) return;

	if (proof == d._expected_proof) {
		d._status = Type::Resource::COMPLETE;
		d._last_activity_ms = Utilities::OS::ltime();
		DEBUGF("Resource: PRF matched, COMPLETE hash=%s", d._hash.toHex().c_str());
		//p if self.segment_index == self.total_segments:
		//p     # If all segments were processed, we'll
		//p     # signal that the resource sending concluded
		// (Resource.py:777-792) Only the FINAL segment fires the
		// application's concluded callback; upstream then closes the
		// input file (the port unlinks its on-disk equivalent).
		if (d._segment_index == d._total_segments) {
			if (d._callbacks._concluded) {
				try { d._callbacks._concluded(*this); }
				catch (const std::exception& e) {
					ERRORF("Resource::on_proof: concluded callback threw: %s", e.what());
				}
			}
			_release_input_file();
		}
		//p else: # Otherwise we'll recursively create the
		//p       # next segment of the resource
		// (Resource.py:793-810) A proven non-final segment chains the next
		// segment over the same link, with no application callback.
		else {
			_advertise_next_segment();
		}
	}
	else {
		d._status = Type::Resource::CORRUPT;
		WARNINGF("Resource: PRF mismatch for %s — peer's hash differed from our expected_proof",
		         d._hash.toHex().c_str());
		if (d._callbacks._concluded) {
			try { d._callbacks._concluded(*this); }
			catch (const std::exception& e) {
				ERRORF("Resource::on_proof: concluded callback threw: %s", e.what());
			}
		}
		// A corrupt proof ends the whole transfer; the remaining
		// segments will never be read out of the input file.
		_release_input_file();
	}
	// Either way, the spilled ciphertext is no longer useful — the
	// receiver has either acknowledged everything or rejected us.
	_release_ciphertext_file();
}

//p def __prepare_next_segment(self):
void Resource::_advertise_next_segment() {
	assert(_object);
	auto& d = *_object;
	const uint32_t next_index = d._segment_index + 1;
	//p RNS.log(f"Preparing segment {self.segment_index+1} of {self.total_segments} for resource {self}", RNS.LOG_DEBUG)
	DEBUGF("Resource: preparing segment %u of %u for transfer %s",
	       (unsigned)next_index, (unsigned)d._total_segments,
	       d._original_hash.toHex().c_str());

	//p self.next_segment = Resource(self.input_file, self.link,
	//p     callback=self.callback, segment_index=self.segment_index+1,
	//p     original_hash=self.original_hash,
	//p     progress_callback=self.__progress_callback,
	//p     request_id=self.request_id, is_response=self.is_response,
	//p     advertise=False, ...)
	// (Resource.py:754-769) Upstream prepares the next segment on a worker
	// thread while the current one transfers; the port has no threads, so
	// preparation happens here on proof validation — upstream's own
	// single-threaded fallback path (Resource.py:796-798).
	Resource next(Bytes(), d._link, /*advertise=*/false, /*auto_compress=*/false,
	              d._callbacks._concluded, d._callbacks._progress, d._timeout,
	              (int)next_index, d._original_hash, d._request_id, d._is_response);
	auto& nd = *next._object;
	nd._is_split       = true;
	nd._total_segments = d._total_segments;
	nd._data_size      = d._data_size;       // full transfer size, constant across segments
	//p self.input_file = data  (ownership of the spill file moves along the chain)
	nd._input_path     = d._input_path;
	d._input_path.clear();

	// Read the next segment's slice out of the input spill file. Layout
	// matches the constructor: with metadata_size always 0, upstream's
	// first_read_size equals MAX_EFFICIENT_SIZE, so segment k covers
	// [(k-1)*MAX_EFFICIENT_SIZE, k*MAX_EFFICIENT_SIZE) (Resource.py:300-311).
	bool ok = false;
	const size_t MES = Type::Resource::MAX_EFFICIENT_SIZE;
	try {
		microStore::File f = Utilities::OS::open_file(
			nd._input_path.c_str(), microStore::File::ModeRead);
		if (f) {
			const size_t total  = f.size();
			const size_t offset = (size_t)(next_index - 1) * MES;
			if (offset < total &&
			    f.seek((uint32_t)offset, microStore::SeekModeSet) >= 0) {
				const size_t length = std::min(MES, total - offset);
				uint8_t* dst = nd._encrypted.writable(length);
				if (dst != nullptr) {
					size_t got = 0;
					while (got < length) {
						const size_t n = f.read(dst + got, length - got);
						if (n == 0 || n == (size_t)-1) break;
						got += n;
						Utilities::OS::reset_watchdog();
					}
					ok = (got == length);
				}
			}
			f.close();
		}
	}
	catch (const std::exception& e) {
		ERRORF("Resource: next-segment read failed: %s", e.what());
	}

	if (ok) {
		const uint16_t link_mdu = const_cast<Link&>(nd._link).get_mdu();
		ok = next._build_outgoing(link_mdu);
	}
	//p self.next_segment.advertise()
	if (ok) {
		next._send_advertisement();
		ok = (next.status() == Type::Resource::ADVERTISED);
	}
	if (!ok) {
		// Divergence from upstream, where a failed next-segment
		// preparation dies silently on its worker thread and the transfer
		// stalls into the receiver's timeout: we are on the caller's call
		// path and CAN report, so fail the chained segment loudly and let
		// the application's concluded callback see it.
		ERRORF("Resource: could not prepare segment %u of %u; transfer failed",
		       (unsigned)next_index, (unsigned)d._total_segments);
		next._release_ciphertext_file();
		next._release_input_file();
		nd._status = Type::Resource::FAILED;
		if (nd._callbacks._concluded) {
			try { nd._callbacks._concluded(next); }
			catch (const std::exception& e) {
				ERRORF("Resource::_advertise_next_segment: concluded callback threw: %s", e.what());
			}
		}
	}
}

const Bytes& Resource::plaintext() const {
	assert(_object);
	// Receiver: post-assembly decrypted body. Sender: empty.
	if (!_object->_initiator) return _object->_plaintext;
	return _object->_encrypted;
}

void Resource::_assemble_and_deliver() {
	auto& d = *_object;
	d._status = Type::Resource::ASSEMBLING;
	d._last_activity_ms = Utilities::OS::ltime();

	// This whole function runs inside the firmware's main-loop tick,
	// which holds rns_lock. The work it does — re-reading the assembled
	// blob, SHA-256ing it, decrypting via the Link key, and firing the
	// concluded callback (which writes attachment bytes to LittleFS) —
	// can easily exceed the 5 s task watchdog window for a ~12 KB
	// resource. We reset the WDT at safe progress points so a long
	// receive doesn't reboot the device.
	Utilities::OS::reset_watchdog();

	//p self.last_resource_window = resource.window
	//p self.last_resource_eifr = resource.eifr
	// Upstream records these inside Link.resource_concluded
	// (Link.py:1285-1290) while the resource is still registered, on
	// COMPLETE and CORRUPT alike (assemble() concludes on every outcome,
	// Resource.py:712). Both values are final once assembly starts, so the
	// port records them up front — they seed the next incoming resource,
	// notably the next segment of a split transfer.
	d._link.last_resource_window(d._window);
	d._link.last_resource_eifr(d._eifr_bps);

	// Decrypt the assembled ciphertext via the Link key, then strip the
	// random_hash prefix the sender prepended before encryption. This
	// matches RNS Resource.py assemble(): decrypt the stream, strip the
	// random hash, *then* verify the content hash over the plaintext.
	const Bytes assembled = d._buffer->read_all();
	// The per-segment receive buffer's job ends here. Discard now so the
	// flash temp file + quota are released before the next segment's ADV
	// guard runs, instead of at sweep-time destruction. (read_all returned
	// either a copy or a shared handle to the heap data, both safe.)
	d._buffer->discard();
	Utilities::OS::reset_watchdog();
	Bytes decrypted;
	try {
		decrypted = d._link.decrypt(assembled);
		Utilities::OS::reset_watchdog();
	}
	catch (const std::exception& e) {
		ERRORF("Resource: Link.decrypt failed: %s", e.what());
		_conclude_corrupt_segment();
		return;
	}
	if (decrypted.size() < Type::Resource::RANDOM_HASH_SIZE) {
		ERROR("Resource: decrypted body too short to contain random_hash prefix");
		_conclude_corrupt_segment();
		return;
	}
	// This SEGMENT's cleartext. Only becomes _plaintext directly for
	// single-segment transfers — for split transfers it is appended to
	// the cross-segment store, and _plaintext is the full concatenation
	// loaded back on the final segment.
	Bytes seg_plaintext(decrypted.data() + Type::Resource::RANDOM_HASH_SIZE,
	                    decrypted.size() - Type::Resource::RANDOM_HASH_SIZE);

	// Verify the resource hash over the *plaintext* payload + random_hash
	// salt, full 32-byte SHA-256 — matching upstream RNS (Resource.py:683)
	// and the sender's `Identity::full_hash(plaintext + random_hash)`.
	const Bytes computed_hash =
		Identity::full_hash(seg_plaintext + d._random_hash);
	Utilities::OS::reset_watchdog();
	if (computed_hash != d._hash) {
		WARNINGF("Resource: assembled hash mismatch for %s — corrupt",
		         d._hash.toHex().c_str());
		_conclude_corrupt_segment();
		return;
	}

	//p proof = RNS.Identity.full_hash(self.data+self.hash)
	// The proof covers this SEGMENT's cleartext; compute it before
	// _plaintext is (for the final segment) replaced by the full
	// concatenation.
	const Bytes proof = Identity::full_hash(seg_plaintext + d._hash);

	//p self.file = open(self.storagepath, "ab"); self.file.write(data)
	// (Resource.py:697-699) Append the verified segment cleartext to the
	// cross-segment store so a multi-MiB transfer never dwells fully in
	// RAM between segments.
	if (d._is_split) {
		bool append_ok = false;
		try {
			microStore::File f = Utilities::OS::open_file(
				d._segment_store_path.c_str(), microStore::File::ModeAppend);
			if (f) {
				// Defense the advertised `d` gate can't give us: a sender
				// could advertise a small full-size yet keep chaining
				// 1 MiB segments. Track the cumulative store size and
				// abort (RESOURCE_RCL + cleanup via cancel()) when it
				// would exceed the firmware cap.
				const size_t store_size = f.size();
				if (store_size + seg_plaintext.size() > RNS::resource_max_incoming()) {
					f.close();
					NOTICEF("Resource: cumulative split size %zu exceeds firmware cap; aborting",
					        store_size + seg_plaintext.size());
					cancel();
					return;
				}
				size_t written = 0;
				const size_t CHUNK = 64 * 1024;
				while (written < seg_plaintext.size()) {
					const size_t n = std::min(CHUNK, seg_plaintext.size() - written);
					if (f.write(seg_plaintext.data() + written, n) != n) break;
					written += n;
					Utilities::OS::reset_watchdog();
				}
				f.flush();
				f.close();
				append_ok = (written == seg_plaintext.size());
			}
		}
		catch (const std::exception& e) {
			ERRORF("Resource: segment store append failed: %s", e.what());
		}
		if (!append_ok) {
			ERRORF("Resource: could not persist segment %u/%u; aborting transfer",
			       (unsigned)d._segment_index, (unsigned)d._total_segments);
			cancel();   // sends RESOURCE_RCL, releases the store, fires FAILED
			return;
		}
	}

	d._status = Type::Resource::COMPLETE;
	d._last_activity_ms = Utilities::OS::ltime();
	DEBUGF("Resource: assembled %s (%zu plaintext bytes, segment %u/%u)",
	       d._hash.toHex().c_str(), seg_plaintext.size(),
	       (unsigned)d._segment_index, (unsigned)d._total_segments);

	// Send the PRF before firing the callback — the sender wants to know
	// we got the bytes before we go off and process them, otherwise its
	// MAX_RETRIES timer might fire while we're still on the callback.
	// (Upstream order too: prove() precedes the final-segment delivery,
	// Resource.py:702 vs :714.)
	_send_proof(proof);
	Utilities::OS::reset_watchdog();

	//p if self.segment_index == self.total_segments:
	if (d._segment_index == d._total_segments) {
		if (d._is_split) {
			//p self.data = open(self.storagepath, "rb") ... os.unlink(self.storagepath)
			// (Resource.py:726-733) Load the full concatenation back for
			// the data()/plaintext() accessors the concluded callback
			// reads, then drop the store.
			seg_plaintext = Bytes();
			decrypted = Bytes();
			bool load_ok = false;
			try {
				microStore::File f = Utilities::OS::open_file(
					d._segment_store_path.c_str(), microStore::File::ModeRead);
				if (f) {
					const size_t total = f.size();
					uint8_t* dst = d._plaintext.writable(total);
					if (dst != nullptr) {
						size_t got = 0;
						while (got < total) {
							const size_t n = f.read(dst + got, total - got);
							if (n == 0 || n == (size_t)-1) break;
							got += n;
							Utilities::OS::reset_watchdog();
						}
						load_ok = (got == total);
					}
					f.close();
				}
			}
			catch (const std::exception& e) {
				ERRORF("Resource: segment store read-back failed: %s", e.what());
			}
			_release_segment_store();
			if (!load_ok) {
				// The proof is already out (the sender legitimately
				// completed its job); only the local hand-off failed.
				ERROR("Resource: could not load assembled split transfer; delivering FAILED");
				d._plaintext = Bytes();
				d._status = Type::Resource::FAILED;
			}
		}
		else {
			d._plaintext = seg_plaintext;
		}

		if (d._callbacks._concluded) {
			try { d._callbacks._concluded(*this); }
			catch (const std::exception& e) {
				ERRORF("Resource::_assemble: concluded callback threw: %s", e.what());
			}
			// The concluded callback in LXMFGateway writes any attachment
			// blobs to LittleFS, which can block for hundreds of ms on
			// fragmented flash. Reset again on the way out.
			Utilities::OS::reset_watchdog();
		}
	}
	else {
		//p RNS.log("Resource segment "+str(self.segment_index)+" of "+str(self.total_segments)+" received, waiting for next segment to be announced", RNS.LOG_DEBUG)
		// (Resource.py:737-738) Non-final segment: no application callback;
		// the segment's bytes live in the store until the final segment.
		DEBUGF("Resource: segment %u of %u received, waiting for next segment to be announced",
		       (unsigned)d._segment_index, (unsigned)d._total_segments);
	}
}

// Terminal CORRUPT helper for the receive-assembly paths. Upstream fires
// the application callback from assemble() only when segment_index ==
// total_segments (Resource.py:714-729); a corrupt non-final segment just
// logs and leaves the rest to the sender's proof timeout. Divergence from
// upstream: the cross-segment store is released here in every corrupt
// case (the transfer can never complete once a segment is corrupt) —
// upstream leaves the file to a periodic cache cleaner the port doesn't
// have.
void Resource::_conclude_corrupt_segment() {
	auto& d = *_object;
	d._status = Type::Resource::CORRUPT;
	_release_segment_store();
	if (d._segment_index == d._total_segments) {
		if (d._callbacks._concluded) {
			try { d._callbacks._concluded(*this); }
			catch (const std::exception& e) {
				ERRORF("Resource::_assemble: concluded callback threw: %s", e.what());
			}
		}
	}
}

void Resource::_send_proof(const Bytes& proof) {
	auto& d = *_object;
	// PRF body = resource_hash(32) || SHA-256(segment plaintext || hash),
	// matching upstream RNS (Resource.py:744-745). The resource hash
	// prefix lets the sender route the proof to the right outgoing
	// resource; the sender pre-computed the proof tail at build time as
	// _expected_proof.
	Bytes body;
	body.append(d._hash);
	body.append(proof);
	try {
		Packet prf_packet(d._link, body,
		                  Type::Packet::PROOF, Type::Packet::RESOURCE_PRF);
		prf_packet.send();
	}
	catch (const std::exception& e) {
		ERRORF("Resource::_send_proof: PRF send failed: %s", e.what());
		return;
	}
	DEBUGF("Resource: sent PRF for %s", d._hash.toHex().c_str());
}

// --------------------------------------------------------------------------
// Sender REQ handling
//
// Receiver has asked for a set of parts identified by map_hash. We scan
// our pre-built _map_full (one 4-byte slot per part) to find each
// requested hash, then send the matching part as a RESOURCE packet. If
// the receiver's REQ also signals
// hashmap-exhausted, we figure out which HMU segment they need next and
// emit it. Robustness: receivers may legitimately re-request parts
// (proof timeout, retry) — we don't track sent_parts as a hard mutex,
// just resend.
// --------------------------------------------------------------------------

void Resource::on_request(const Bytes& body) {
	assert(_object);
	auto& d = *_object;
	if (!d._initiator) return;
	if (d._status == Type::Resource::FAILED ||
	    d._status == Type::Resource::COMPLETE) return;

	// A REQ means the receiver still wants parts, so resume transferring even
	// if we'd optimistically moved to AWAITING_PROOF after sending the last
	// part (upstream Resource.py:975 — any non-TRANSFERRING status resets).
	if (d._status == Type::Resource::ADVERTISED ||
	    d._status == Type::Resource::AWAITING_PROOF) {
		d._status = Type::Resource::TRANSFERRING;
	}
	d._last_activity_ms = Utilities::OS::ltime();
	d._retries_left = Type::Resource::MAX_RETRIES;

	// Resource hash is the full 32-byte SHA-256 on the wire (RNS
	// Identity.HASHLENGTH//8), not the 16-byte truncated link hash.
	const uint8_t HASHLEN  = Type::Identity::HASHLENGTH / 8;
	const uint8_t MAPLEN   = Type::Resource::MAPHASH_LEN;
	if (body.size() < 1 + HASHLEN) {
		WARNING("on_request: body too short");
		return;
	}

	const uint8_t exhausted = body[0];
	size_t cursor = 1;
	const uint8_t* last_map_hash = nullptr;
	if (exhausted == Type::Resource::HASHMAP_IS_EXHAUSTED) {
		if (body.size() < 1 + MAPLEN + HASHLEN) {
			WARNING("on_request: exhausted REQ truncated");
			return;
		}
		last_map_hash = body.data() + cursor;
		cursor += MAPLEN;
	}
	Bytes peer_hash(body.data() + cursor, HASHLEN);
	cursor += HASHLEN;
	if (peer_hash != d._hash) {
		DEBUG("on_request: hash mismatch; not for us");
		return;
	}

	// Send each requested part. Each send() queues a packet to the
	// modem (encrypt + frame); a full REQ batch can chain several
	// sends and push the loop tick past the WDT window if the radio
	// queue is also draining.
	uint16_t resent = 0;
	while (cursor + MAPLEN <= body.size()) {
		const uint8_t* req_map_hash = body.data() + cursor;
		cursor += MAPLEN;
		for (uint16_t i = 0; i < d._parts_count; ++i) {
			if (memcmp(d._map_full.data() + (size_t)i * MAPLEN,
			           req_map_hash, MAPLEN) == 0) {
				Bytes part_data;
				if (!_load_part(i, part_data)) {
					ERRORF("on_request: _load_part(%u) failed", (unsigned)i);
					break;
				}
				try {
					Packet part_packet(d._link, part_data,
					                   Type::Packet::DATA, Type::Packet::RESOURCE);
					part_packet.send();
					resent++;
					d._sent_parts++;
					// Count DISTINCT parts (upstream bumps sent_parts only on a
					// part's first send) so we know when every part is out.
					if (i < d._part_sent.size() && !d._part_sent[i]) {
						d._part_sent[i] = true;
						d._distinct_sent++;
					}
					d._last_part_sent_ms = Utilities::OS::ltime();
				}
				catch (const std::exception& e) {
					ERRORF("on_request: part %u send failed: %s", (unsigned)i, e.what());
				}
				break;
			}
		}
		Utilities::OS::reset_watchdog();
	}
	DEBUGF("on_request: sent %u parts (exhausted=%s)", (unsigned)resent,
	       exhausted == Type::Resource::HASHMAP_IS_EXHAUSTED ? "yes" : "no");

	// If the receiver's hashmap is exhausted, derive which segment they
	// need next and emit it. last_map_hash sits at the boundary between
	// what they have and what they don't; find which index it maps to,
	// then the next HMU segment is floor(index / HASHMAP_MAX_LEN) + 1.
	if (exhausted == Type::Resource::HASHMAP_IS_EXHAUSTED && last_map_hash != nullptr) {
		const uint16_t HMU_MAX = Type::Resource::ResourceAdvertisement::HASHMAP_MAX_LEN;
		uint16_t last_index = 0;
		for (uint16_t i = 0; i < d._parts_count; ++i) {
			if (memcmp(d._map_full.data() + (size_t)i * MAPLEN,
			           last_map_hash, MAPLEN) == 0) {
				last_index = i;
				break;
			}
		}
		const uint8_t next_seg = (uint8_t)((last_index / HMU_MAX) + 1);
		const size_t next_start = (size_t)next_seg * HMU_MAX * Type::Resource::MAPHASH_LEN;
		if (next_start < d._map_full.size()) {
			_send_hmu(next_seg);
		}
	}

	// Every part has now been sent at least once -> wait only for the proof.
	// AWAITING_PROOF uses a tight timeout in the watchdog (vs the generous
	// part-request wait); a later REQ for a missing part flips us back to
	// TRANSFERRING at the top of on_request. retries_left is reset to the
	// upstream proof-retry budget (Resource.py:1054-1056).
	if (d._distinct_sent >= d._parts_count && d._parts_count > 0) {
		d._status = Type::Resource::AWAITING_PROOF;
		d._retries_left = 3;
	}

	// Fire the sender-side progress callback (upstream request() does this at
	// the end of each REQ batch). uR previously only fired progress on the
	// receiver (on_part), so outbound transfers reported no progress. The
	// outbound LXMF trampoline reads get_progress() = _sent_parts/_parts_count
	// to drive the SPA's outbound transfer row, mirroring on_part.
	if (d._callbacks._progress) {
		try { d._callbacks._progress(*this); }
		catch (const std::exception& e) {
			ERRORF("Resource::on_request: progress callback threw: %s", e.what());
		}
	}
}


void Resource::_send_hmu(uint8_t segment_index) {
	assert(_object);
	auto& d = *_object;
	const uint16_t HMU_MAX = Type::Resource::ResourceAdvertisement::HASHMAP_MAX_LEN;

	const size_t start = (size_t)segment_index * HMU_MAX * Type::Resource::MAPHASH_LEN;
	if (start >= d._map_full.size()) return;
	const size_t end =
		std::min(d._map_full.size(), start + (size_t)HMU_MAX * Type::Resource::MAPHASH_LEN);

	Bytes hashmap_seg(d._map_full.data() + start, end - start);

	// Body: 32 B resource hash || msgpack([segment_index, hashmap_seg])
	MsgPack::Packer packer;
	packer.to_array((uint32_t)segment_index, hashmap_seg);
	Bytes body;
	body.append(d._hash);
	body.append(Bytes(packer.data(), packer.size()));

	try {
		Packet hmu_packet(d._link, body, Type::Packet::DATA, Type::Packet::RESOURCE_HMU);
		hmu_packet.send();
	}
	catch (const std::exception& e) {
		ERRORF("Resource: HMU send failed (seg=%u): %s", segment_index, e.what());
		return;
	}
	DEBUGF("Resource: sent HMU segment=%u (%u hashes)",
	       segment_index,
	       (unsigned)((end - start) / Type::Resource::MAPHASH_LEN));
}


// --------------------------------------------------------------------------
// Cancel paths + timeout watchdog
// --------------------------------------------------------------------------

void Resource::cancel() {
	assert(_object);
	auto& d = *_object;
	if (d._status == Type::Resource::COMPLETE ||
	    d._status == Type::Resource::FAILED ||
	    d._status == Type::Resource::CORRUPT) return;

	// Sender abandons -> send ICL; receiver abandons -> send RCL.
	const Type::Packet::context_types ctx =
		d._initiator ? Type::Packet::RESOURCE_ICL : Type::Packet::RESOURCE_RCL;
	try {
		Packet cancel_packet(d._link, d._hash, Type::Packet::DATA, ctx);
		cancel_packet.send();
	}
	catch (const std::exception& e) {
		WARNINGF("Resource::cancel: cancel packet send failed: %s", e.what());
	}
	d._status = Type::Resource::FAILED;
	if (d._buffer) d._buffer->discard();
	// Spill files are no longer needed: the sender's ciphertext + split
	// input file, and the receiver's cross-segment store (a cancelled
	// segment ends the whole split transfer). All idempotent no-ops when
	// the respective path is empty.
	_release_ciphertext_file();
	_release_input_file();
	_release_segment_store();
	DEBUGF("Resource: cancelled (%s side) hash=%s",
	       d._initiator ? "sender" : "receiver", d._hash.toHex().c_str());

	if (d._callbacks._concluded) {
		try { d._callbacks._concluded(*this); }
		catch (const std::exception& e) {
			ERRORF("Resource::cancel: concluded callback threw: %s", e.what());
		}
	}
}

void Resource::on_initiator_cancel(const Bytes& sender_hash) {
	assert(_object);
	auto& d = *_object;
	if (d._initiator) return;       // ICL is for receivers
	if (sender_hash != d._hash) return;
	if (d._status == Type::Resource::COMPLETE ||
	    d._status == Type::Resource::FAILED ||
	    d._status == Type::Resource::CORRUPT) return;

	NOTICEF("Resource: received ICL (sender abandoned) hash=%s",
	        d._hash.toHex().c_str());
	d._status = Type::Resource::FAILED;
	if (d._buffer) d._buffer->discard();
	// The sender abandoning any segment ends the whole split transfer;
	// drop the cross-segment store with it.
	_release_segment_store();
	if (d._callbacks._concluded) {
		try { d._callbacks._concluded(*this); }
		catch (const std::exception& e) {
			ERRORF("Resource::on_initiator_cancel: callback threw: %s", e.what());
		}
	}
}

void Resource::on_receiver_cancel(const Bytes& receiver_hash) {
	assert(_object);
	auto& d = *_object;
	if (!d._initiator) return;       // RCL is for senders
	if (receiver_hash != d._hash) return;
	if (d._status == Type::Resource::COMPLETE ||
	    d._status == Type::Resource::FAILED ||
	    d._status == Type::Resource::CORRUPT) return;

	NOTICEF("Resource: received RCL (receiver refused) hash=%s",
	        d._hash.toHex().c_str());
	d._status = Type::Resource::FAILED;
	// The refused segment ends the whole transfer: drop the spilled
	// ciphertext (previously leaked on this path) and, for split
	// transfers, the full-plaintext input file.
	_release_ciphertext_file();
	_release_input_file();
	if (d._callbacks._concluded) {
		try { d._callbacks._concluded(*this); }
		catch (const std::exception& e) {
			ERRORF("Resource::on_receiver_cancel: callback threw: %s", e.what());
		}
	}
}

void Resource::tick(uint64_t now_ms) {
	assert(_object);
	auto& d = *_object;
	if (d._status == Type::Resource::COMPLETE ||
	    d._status == Type::Resource::FAILED ||
	    d._status == Type::Resource::CORRUPT) return;

	double rtt = const_cast<Link&>(d._link).rtt();
	if (rtt <= 0.0) rtt = 2.0;
	const uint64_t adv_timeout_ms =
		(uint64_t)(rtt * Type::Resource::PART_TIMEOUT_FACTOR * 1000.0);
	const uint64_t elapsed = now_ms - d._last_activity_ms;

	if (d._initiator) {
		// Sender. ADVERTISED waiting for REQ: re-send ADV up to
		// MAX_ADV_RETRIES. TRANSFERRING / AWAITING_PROOF: trust the
		// receiver to drive REQ retries — the receiver's window
		// timeout is now EIFR-adapted, so it will keep REQing on
		// airtime-throttled links until either the transfer completes
		// or its own MAX_RETRIES exhausts. Sender's max_wait is
		// generous (MAX_RETRIES * SENDER_GRACE_TIME) so a slow
		// receiver doesn't trigger a premature sender abort while
		// the receiver is still patiently waiting for parts to
		// dribble out of an airtime-capped queue.
		const uint64_t sender_max_wait_ms =
			(uint64_t)(Type::Resource::SENDER_GRACE_TIME * 1000.0) *
			Type::Resource::MAX_RETRIES;
		if (d._status == Type::Resource::ADVERTISED && elapsed > adv_timeout_ms) {
			if (d._adv_retries_left > 0) {
				d._adv_retries_left--;
				DEBUGF("Resource: ADV retry (%u left)", (unsigned)d._adv_retries_left);
				_send_advertisement();
			}
			else {
				NOTICEF("Resource: ADV timeout exhausted, FAILED hash=%s",
				        d._hash.toHex().c_str());
				cancel();
			}
		}
		else if (d._status == Type::Resource::TRANSFERRING &&
		         elapsed > sender_max_wait_ms) {
			NOTICEF("Resource: transfer timeout, FAILED hash=%s (no receiver activity for %u ms)",
			        d._hash.toHex().c_str(), (unsigned)elapsed);
			cancel();
		}
		else if (d._status == Type::Resource::AWAITING_PROOF) {
			// All parts are out; only the small proof remains. Use a tight
			// timeout (upstream Resource.py:635-654 PROOF_TIMEOUT_FACTOR) rather
			// than the generous part-request wait above, so a lost proof fails
			// fast and the LXMF layer re-sends the whole message (the receiver
			// dedups the re-delivery). A late REQ for a missing part flips us
			// back to TRANSFERRING in on_request. Upstream also issues a
			// packet-cache request per retry; that path is a no-op on a 2-node
			// link, so we omit it and just re-wait the proof window. `rtt` is
			// the link rtt computed at the top of the watchdog (2.0 s fallback).
			const uint64_t proof_wait_ms =
				(uint64_t)((rtt * Type::Resource::PROOF_TIMEOUT_FACTOR +
				            Type::Resource::SENDER_GRACE_TIME) * 1000.0);
			if (now_ms > d._last_part_sent_ms + proof_wait_ms) {
				if (d._retries_left == 0) {
					NOTICEF("Resource: all parts sent but no proof, FAILED hash=%s",
					        d._hash.toHex().c_str());
					cancel();
				}
				else {
					DEBUGF("Resource: proof wait elapsed, %u retries left, hash=%s",
					       (unsigned)d._retries_left, d._hash.toHex().c_str());
					d._retries_left--;
					d._last_part_sent_ms = now_ms;
				}
			}
		}
	}
	else {
		// Receiver. Window timeout is EIFR-based — scales with the
		// observed (or bootstrap-estimated) link rate so airtime-
		// throttled links get proportionally longer waits instead
		// of failing fast.
		//
		// expected_tof = outstanding_parts * sdu * 8 / eifr_bps
		// window_timeout = PART_TIMEOUT_FACTOR_AFTER_RTT * expected_tof
		//                + RETRY_GRACE + retries_used * PER_RETRY_DELAY
		//
		// Ported from upstream RNS Resource.py:596-617. On a 1%-capped
		// EU sub-band carrying a 4 KB body (18 parts, ~250 ms airtime
		// each), this yields ~115 s expected window TOF and a ~230 s
		// timeout. Without EIFR the receiver would fail in 4 s.
		if (d._status != Type::Resource::TRANSFERRING) return;

		if (d._eifr_bps <= 0.0) update_eifr();
		const double sdu_bits = (double)d._sdu * 8.0;
		const double outstanding = (double)d._outstanding_parts;
		const double expected_tof_s = (outstanding * sdu_bits) / d._eifr_bps;
		const double retries_used = (double)(Type::Resource::MAX_RETRIES - d._retries_left);
		const double extra_wait_s = retries_used * Type::Resource::PER_RETRY_DELAY;
		const double window_timeout_s =
			Type::Resource::PART_TIMEOUT_FACTOR_AFTER_RTT * expected_tof_s
			+ Type::Resource::RETRY_GRACE_TIME
			+ extra_wait_s;
		const uint64_t window_timeout_ms = (uint64_t)(window_timeout_s * 1000.0);

		if (elapsed > window_timeout_ms) {
			if (d._retries_left > 0) {
				d._retries_left--;
				// Shrink the window on a part timeout so a struggling link
				// converges to a smaller, more reliable window — faithful to
				// upstream RNS Resource.py:612-617.
				if (d._window > d._window_min) {
					d._window -= 1;
					if (d._window_max > d._window_min) {
						d._window_max -= 1;
						if ((d._window_max - d._window) > (Type::Resource::WINDOW_FLEXIBILITY - 1)) {
							d._window_max -= 1;
						}
					}
				}
				DEBUGF("Resource: REQ retry (%u left, window=%u/%u, window_timeout=%u ms, eifr=%.0f bps)",
				       (unsigned)d._retries_left, (unsigned)d._window, (unsigned)d._window_max,
				       (unsigned)window_timeout_ms, d._eifr_bps);
				d._outstanding_parts = 0;
				send_part_request();
			}
			else {
				NOTICEF("Resource: receive timeout, FAILED hash=%s (eifr=%.0f bps, window=%u ms)",
				        d._hash.toHex().c_str(), d._eifr_bps,
				        (unsigned)window_timeout_ms);
				cancel();
			}
		}
	}
}

/*
:returns: The current progress of the resource transfer as a *float* between 0.0 and 1.0.

Port of upstream get_progress (Resource.py:1107-1162): split transfers
report WHOLE-transfer progress by counting each prior segment as
ceil(MAX_EFFICIENT_SIZE/sdu) parts and scaling a short (final) segment up
by the same factor. The sender counts DISTINCT parts sent (upstream bumps
sent_parts only on a part's first send), not resends.
*/
float Resource::get_progress() const {
	assert(_object);
	const auto& d = *_object;
	//p if self.status == RNS.Resource.COMPLETE and self.segment_index == self.total_segments: return 1.0
	if (d._status == Type::Resource::COMPLETE &&
	    d._segment_index == d._total_segments) return 1.0f;
	if (d._parts_count == 0 || d._sdu == 0) return 0.0f;

	const double done = d._initiator ? (double)d._distinct_sent
	                                 : (double)d._received_count;
	double processed_parts;
	double progress_total_parts;
	if (!d._is_split) {
		//p self.processed_parts = self.sent_parts / self.received_count
		//p self.progress_total_parts = float(self.total_parts)
		processed_parts      = done;
		progress_total_parts = (double)d._parts_count;
	}
	else {
		//p max_parts_per_segment = math.ceil(Resource.MAX_EFFICIENT_SIZE/self.sdu)
		//p previously_processed_parts = processed_segments*max_parts_per_segment
		//p if current_segment_parts < max_parts_per_segment:
		//p     current_segment_factor = max_parts_per_segment / current_segment_parts
		//p else: current_segment_factor = 1
		//p self.processed_parts = previously_processed_parts + <done>*current_segment_factor
		//p self.progress_total_parts = self.total_segments*max_parts_per_segment
		const double max_parts_per_segment =
			std::ceil((double)Type::Resource::MAX_EFFICIENT_SIZE / (double)d._sdu);
		const double previously_processed_parts =
			(double)(d._segment_index - 1) * max_parts_per_segment;
		double current_segment_factor = 1.0;
		if ((double)d._parts_count < max_parts_per_segment) {
			current_segment_factor = max_parts_per_segment / (double)d._parts_count;
		}
		processed_parts      = previously_processed_parts + done * current_segment_factor;
		progress_total_parts = (double)d._total_segments * max_parts_per_segment;
	}

	//p progress = min(1.0, self.processed_parts / self.progress_total_parts)
	return (float)std::min(1.0, processed_parts / progress_total_parts);
}

void Resource::set_concluded_callback(Callbacks::concluded callback) {
	assert(_object);
	_object->_callbacks._concluded = callback;
}

void Resource::set_progress_callback(Callbacks::progress callback) {
	assert(_object);
	_object->_callbacks._progress = callback;
}


std::string Resource::toString() const {
	if (!_object) {
		return "";
	}
	return "{Resource:" + _object->_hash.toHex() + "}";
}

// getters
const Bytes& Resource::hash() const {
	assert(_object);
	return _object->_hash;
}

const Bytes& Resource::original_hash() const {
	assert(_object);
	return _object->_original_hash;
}

uint32_t Resource::segment_index() const {
	assert(_object);
	return _object->_segment_index;
}

//p def get_segments(self): return self.total_segments
uint32_t Resource::total_segments() const {
	assert(_object);
	return _object->_total_segments;
}

const Bytes& Resource::request_id() const {
	assert(_object);
	return _object->_request_id;
}

const Bytes& Resource::data() const {
	assert(_object);
	// Receiver side: the assembled cleartext (upstream's `resource.data`
	// file handle, Resource.py:726). Empty before assembly completes.
	// Sender side: the prepared (eventually encrypted) payload.
	if (!_object->_initiator) return _object->_plaintext;
	return _object->_encrypted;
}

const Type::Resource::status Resource::status() const {
	assert(_object);
	return _object->_status;
}

const size_t Resource::size() const {
	assert(_object);
	return _object->_transfer_size;
}

const size_t Resource::total_size() const {
	assert(_object);
	return _object->_data_size;
}

const Link& Resource::link() const {
	assert(_object);
	return _object->_link;
}

// setters

