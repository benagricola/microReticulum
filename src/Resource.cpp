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
		else if (key == "i") { uint32_t v; if (!r.read_uint(v)) return false; _i = uint8_t(v); got_i = true; }
		else if (key == "l") { uint32_t v; if (!r.read_uint(v)) return false; _l = uint8_t(v); got_l = true; }
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
	_object->_segment_index     = (uint8_t)segment_index;
	_object->_total_segments    = 1;        // single-segment port; always 1
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

	if (advertise) {
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
	d._data_size     = d._transfer_size;   // _d == _t (no compression in this port)

	BO_HEAP("post-encrypt");

	{
		const size_t firmware_cap = RNS::resource_max_incoming();
		if (d._transfer_size > firmware_cap) {
			ERRORF("Resource: transfer size %u exceeds firmware cap %u",
			       (unsigned)d._transfer_size,
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
	d._is_split        = adv.split();
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
		if (d._callbacks._concluded) {
			try { d._callbacks._concluded(*this); }
			catch (const std::exception& e) {
				ERRORF("Resource::on_proof: concluded callback threw: %s", e.what());
			}
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
	}
	// Either way, the spilled ciphertext is no longer useful — the
	// receiver has either acknowledged everything or rejected us.
	_release_ciphertext_file();
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

	// Decrypt the assembled ciphertext via the Link key, then strip the
	// random_hash prefix the sender prepended before encryption. This
	// matches RNS Resource.py assemble(): decrypt the stream, strip the
	// random hash, *then* verify the content hash over the plaintext.
	const Bytes assembled = d._buffer->read_all();
	Utilities::OS::reset_watchdog();
	Bytes decrypted;
	try {
		decrypted = d._link.decrypt(assembled);
		Utilities::OS::reset_watchdog();
	}
	catch (const std::exception& e) {
		ERRORF("Resource: Link.decrypt failed: %s", e.what());
		d._status = Type::Resource::CORRUPT;
		if (d._callbacks._concluded) {
			try { d._callbacks._concluded(*this); }
			catch (const std::exception& cb_e) {
				ERRORF("Resource::_assemble: concluded callback threw: %s", cb_e.what());
			}
		}
		return;
	}
	if (decrypted.size() < Type::Resource::RANDOM_HASH_SIZE) {
		ERROR("Resource: decrypted body too short to contain random_hash prefix");
		d._status = Type::Resource::CORRUPT;
		return;
	}
	d._plaintext = Bytes(decrypted.data() + Type::Resource::RANDOM_HASH_SIZE,
	                     decrypted.size() - Type::Resource::RANDOM_HASH_SIZE);

	// Verify the resource hash over the *plaintext* payload + random_hash
	// salt, full 32-byte SHA-256 — matching upstream RNS (Resource.py:694)
	// and the sender's `Identity::full_hash(plaintext + random_hash)`.
	const Bytes computed_hash =
		Identity::full_hash(d._plaintext + d._random_hash);
	Utilities::OS::reset_watchdog();
	if (computed_hash != d._hash) {
		WARNINGF("Resource: assembled hash mismatch for %s — corrupt",
		         d._hash.toHex().c_str());
		d._status = Type::Resource::CORRUPT;
		if (d._callbacks._concluded) {
			try { d._callbacks._concluded(*this); }
			catch (const std::exception& e) {
				ERRORF("Resource::_assemble: concluded callback threw: %s", e.what());
			}
		}
		return;
	}

	d._status = Type::Resource::COMPLETE;
	d._last_activity_ms = Utilities::OS::ltime();
	DEBUGF("Resource: assembled %s (%zu plaintext bytes)",
	       d._hash.toHex().c_str(), d._plaintext.size());

	// Send the PRF before firing the callback — the sender wants to know
	// we got the bytes before we go off and process them, otherwise its
	// MAX_RETRIES timer might fire while we're still on the callback.
	_send_proof();
	Utilities::OS::reset_watchdog();

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

void Resource::_send_proof() {
	auto& d = *_object;
	// PRF body = resource_hash(32) || SHA-256(plaintext || hash), matching
	// upstream RNS (Resource.py:755-756). The proof is computed over the
	// decrypted plaintext, and the resource hash prefix lets the sender
	// route the proof to the right outgoing resource. The sender
	// pre-computed the proof tail at build time as _expected_proof.
	const Bytes proof = Identity::full_hash(d._plaintext + d._hash);
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

	if (d._status == Type::Resource::ADVERTISED) {
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


void Resource::validate_proof(const Bytes& proof_data) {
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
	// Sender's spilled ciphertext (if any) is no longer needed.
	_release_ciphertext_file();
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
		else if ((d._status == Type::Resource::TRANSFERRING ||
		          d._status == Type::Resource::AWAITING_PROOF) &&
		         elapsed > sender_max_wait_ms) {
			NOTICEF("Resource: transfer timeout, FAILED hash=%s (no receiver activity for %u ms)",
			        d._hash.toHex().c_str(), (unsigned)elapsed);
			cancel();
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
*/
float Resource::get_progress() const {
	assert(_object);
	const auto& d = *_object;
	if (d._parts_count == 0) return 0.0f;
	const uint16_t done = d._initiator ? d._sent_parts : d._received_count;
	if (done >= d._parts_count) return 1.0f;
	return (float)done / (float)d._parts_count;
}
/*
	// Original (Python-style) implementation kept for reference. Single-
	// segment only is the firmware's stance, so the segment-index +
	// total_size math is unused; the simple done/total ratio above is
	// equivalent for our s=1, non-split case.
	assert(_object);
	if (_object->_initiator) {
		_object->_processed_parts = (_object->_segment_index-1)*math.ceil(Type::Resource::MAX_EFFICIENT_SIZE/Type::Resource::SDU);
		_object->_processed_parts += _object->sent_parts;
		_object->_progress_total_parts = float(_object->grand_total_parts);
	}
	else {
		_object->_processed_parts = (_object->_segment_index-1)*math.ceil(Type::Resource::MAX_EFFICIENT_SIZE/Type::Resource::SDU);
		_object->_processed_parts += _object->_received_count;
		if (_object->split) {
			_object->progress_total_parts = float(math.ceil(_object->total_size/Type::Resource::SDU));
		}
		else {
			_object->progress_total_parts = float(_object->total_parts);
		}
	}

	return (float)_object->processed_parts / (float)_object->progress_total_parts;
*/

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

const Bytes& Resource::request_id() const {
	assert(_object);
	return _object->_request_id;
}

const Bytes& Resource::data() const {
	assert(_object);
	// Sender side: the prepared (eventually encrypted) payload.
	// Receiver side: callers should use the buffer through ResourceBuffer
	// once assembly completes; that hookup lands with the receiver part
	// assembly along with the resource_concluded callback wiring.
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

