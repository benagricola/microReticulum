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
	// pack-and-send pipeline is built out in plan step 5. We just stash
	// the inputs for now.
	_object->_initiator   = true;
	_object->_is_request  = !is_response;
	_object->_is_response = is_response;
	_object->_request_id  = request_id;
	_object->_encrypted   = data;       // placeholder; sender pipeline encrypts via Link in step 5
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
// Sender pipeline (plan step 5)
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

	// Random salt prepended to the plaintext before encryption. Makes the
	// per-part map_hashes unpredictable to anyone without the Link key.
	Bytes random_hash = Identity::get_random_hash().left(Type::Resource::RANDOM_HASH_SIZE);
	d._random_hash = random_hash;

	const Bytes plaintext = d._encrypted;   // the constructor stashed plaintext here
	Bytes salted;
	salted.append(random_hash);
	salted.append(plaintext);

	// Encrypt via the Link's derived key (Fernet over AES-128-CBC).
	// AES on a 12 KB blob takes tens of ms; the per-part loop below
	// adds more. Same WDT story as the receive side. (#60)
	Utilities::OS::reset_watchdog();
	const Bytes encrypted = d._link.encrypt(salted);
	Utilities::OS::reset_watchdog();
	d._encrypted    = encrypted;
	d._transfer_size = (uint32_t)encrypted.size();
	d._data_size     = d._transfer_size;   // _d == _t (no compression in this port)

	if (d._transfer_size > Type::Resource::FIRMWARE_MAX_INCOMING) {
		ERRORF("Resource: transfer size %u exceeds firmware cap %u",
		       (unsigned)d._transfer_size,
		       (unsigned)Type::Resource::FIRMWARE_MAX_INCOMING);
		return false;
	}

	// Resource hash and the proof the receiver will return on completion.
	d._hash           = Identity::truncated_hash(encrypted + random_hash);
	d._expected_proof = Identity::full_hash(encrypted + d._hash);
	if (d._original_hash.empty()) d._original_hash = d._hash;

	// Slice into parts. Each part's map_hash = sha256(part_data || random_hash)[:4].
	const uint16_t sdu = link_mdu;
	d._sdu = sdu;
	const uint32_t n_parts32 = (d._transfer_size + sdu - 1) / sdu;
	if (n_parts32 > 0xFFFF) {
		ERRORF("Resource: too many parts: %u", (unsigned)n_parts32);
		return false;
	}
	const uint16_t n_parts = (uint16_t)n_parts32;
	d._parts_count = n_parts;

	d._parts.clear();      d._parts.reserve(n_parts);
	d._map_hashes.clear(); d._map_hashes.reserve(n_parts);
	d._map_full = Bytes();

	for (uint16_t i = 0; i < n_parts; ++i) {
		const size_t offset = (size_t)i * sdu;
		const size_t length = std::min((size_t)sdu, (size_t)(d._transfer_size - offset));
		Bytes part_data(encrypted.data() + offset, length);

		const Bytes map_hash =
			Identity::full_hash(part_data + random_hash).left(Type::Resource::MAPHASH_LEN);

		d._parts.push_back(part_data);
		d._map_hashes.push_back(map_hash);
		d._map_full.append(map_hash);

		// SHA-256 per part + the vector growth. 30 iterations adds up
		// to a few hundred ms total — keep the WDT happy. (#60)
		if ((i & 0x07) == 0) Utilities::OS::reset_watchdog();
	}

	return true;
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
// Receiver pipeline (plan step 6)
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
	d._sdu             = const_cast<Link&>(link).get_mdu();

	// Allocate the receive buffer. Heap below RAM_BUFFER_THRESHOLD,
	// flash-streamed above. nullptr means flash quota would be exceeded.
	d._buffer = make_resource_buffer(d._transfer_size);
	if (!d._buffer || !d._buffer->open(d._transfer_size)) {
		ERRORF("Resource::accept: failed to allocate buffer for %u-byte resource",
		       (unsigned)d._transfer_size);
		d._status = Type::Resource::FAILED;
		return r;
	}

	// Seed the hashmap with the ADV's first-segment map_hashes. Slots
	// beyond first-segment stay empty until corresponding HMU arrives.
	d._map_hashes.assign(d._parts_count, Bytes());
	const Bytes& adv_map = adv.hashmap();
	const size_t avail_hashes = adv_map.size() / Type::Resource::MAPHASH_LEN;
	for (size_t i = 0; i < avail_hashes && i < d._parts_count; ++i) {
		d._map_hashes[i] = Bytes(adv_map.data() + i * Type::Resource::MAPHASH_LEN,
		                         Type::Resource::MAPHASH_LEN);
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
		if (d._map_hashes[pn].empty()) {
			// Hashmap exhausted at this position — ask sender for more.
			exhausted = Type::Resource::HASHMAP_IS_EXHAUSTED;
			break;
		}
		requested.append(d._map_hashes[pn]);
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
			if (!d._map_hashes[i].empty()) last_known = i;
		}
		body.append(d._map_hashes[last_known]);
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
	DEBUGF("Resource: sent REQ (asking for %u parts, exhausted=%s)",
	       (unsigned)asked,
	       exhausted == Type::Resource::HASHMAP_IS_EXHAUSTED ? "yes" : "no");
}

// --------------------------------------------------------------------------
// Receiver part assembly + PRF emission (plan step 7)
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
	for (uint16_t i = 0; i < d._parts_count; ++i) {
		if (d._parts_received[i]) continue;
		if (d._map_hashes[i].size() != Type::Resource::MAPHASH_LEN) continue;
		if (d._map_hashes[i] == map_hash) { matched = i; break; }
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
	// (#60) Reset receiver retry budget on each successful part. The
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
		// Window done; request the next batch.
		send_part_request();
	}
}

void Resource::on_hashmap_update(const Bytes& body) {
	assert(_object);
	auto& d = *_object;
	const uint8_t HASHLEN = Type::Identity::TRUNCATED_HASHLENGTH / 8;
	if (body.size() < HASHLEN + 3) {
		WARNING("RESOURCE_HMU body too short");
		return;
	}
	// Body: 16 B hash + msgpack([segment, hashmap_bytes])
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
	for (size_t i = 0; i < entries; ++i) {
		const size_t slot = seg_start_index + i;
		if (slot >= d._parts_count) break;
		if (d._map_hashes[slot].empty()) {
			d._map_hashes[slot] = Bytes(hashmap_bytes.data() + i * Type::Resource::MAPHASH_LEN,
			                            Type::Resource::MAPHASH_LEN);
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
	// receive doesn't reboot the device. (#60)
	Utilities::OS::reset_watchdog();

	// Verify the resource hash. We hash the assembled ciphertext + the
	// random_hash salt and truncate to 16 bytes, matching the sender's
	// `Identity::truncated_hash(encrypted + random_hash)`.
	const Bytes assembled = d._buffer->read_all();
	Utilities::OS::reset_watchdog();
	const Bytes computed_hash =
		Identity::truncated_hash(assembled + d._random_hash);
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

	// Decrypt via the Link's key, then strip the random_hash prefix the
	// sender prepended before encryption. Result is the original payload.
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
	// PRF body = SHA-256(assembled || hash). The sender pre-computed the
	// same value at build time as _expected_proof.
	const Bytes proof = Identity::full_hash(d._buffer->read_all() + d._hash);
	try {
		Packet prf_packet(d._link, proof,
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
// Sender REQ handling (plan step 8)
//
// Receiver has asked for a set of parts identified by map_hash. We scan
// our pre-built _map_hashes to find each requested hash, then send the
// matching part as a RESOURCE packet. If the receiver's REQ also signals
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

	const uint8_t HASHLEN  = Type::Identity::TRUNCATED_HASHLENGTH / 8;
	const uint8_t MAPLEN   = Type::Resource::MAPHASH_LEN;
	if (body.size() < 1 + HASHLEN) {
		WARNING("on_request: body too short");
		return;
	}

	const uint8_t exhausted = body[0];
	size_t cursor = 1;
	Bytes last_map_hash;
	if (exhausted == Type::Resource::HASHMAP_IS_EXHAUSTED) {
		if (body.size() < 1 + MAPLEN + HASHLEN) {
			WARNING("on_request: exhausted REQ truncated");
			return;
		}
		last_map_hash = Bytes(body.data() + cursor, MAPLEN);
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
	// queue is also draining. (#60)
	uint16_t resent = 0;
	while (cursor + MAPLEN <= body.size()) {
		Bytes req_map_hash(body.data() + cursor, MAPLEN);
		cursor += MAPLEN;
		for (uint16_t i = 0; i < d._parts_count; ++i) {
			if (d._map_hashes[i] == req_map_hash) {
				try {
					Packet part_packet(d._link, d._parts[i],
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
	if (exhausted == Type::Resource::HASHMAP_IS_EXHAUSTED) {
		const uint16_t HMU_MAX = Type::Resource::ResourceAdvertisement::HASHMAP_MAX_LEN;
		uint16_t last_index = 0;
		for (uint16_t i = 0; i < d._parts_count; ++i) {
			if (d._map_hashes[i] == last_map_hash) { last_index = i; break; }
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

	// Body: 16 B resource hash || msgpack([segment_index, hashmap_seg])
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
// Cancel paths + timeout watchdog (plan step 9)
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

	// Compute the per-window timeout. RTT defaults to a generous fallback
	// when the Link hasn't measured one yet (link just established).
	double rtt = const_cast<Link&>(d._link).rtt();
	if (rtt <= 0.0) rtt = 2.0;
	const uint64_t window_timeout_ms =
		(uint64_t)(rtt * Type::Resource::PART_TIMEOUT_FACTOR_AFTER_RTT * 1000.0);
	const uint64_t adv_timeout_ms =
		(uint64_t)(rtt * Type::Resource::PART_TIMEOUT_FACTOR * 1000.0);
	const uint64_t elapsed = now_ms - d._last_activity_ms;

	if (d._initiator) {
		// Sender. ADVERTISED waiting for REQ: re-send ADV up to
		// MAX_ADV_RETRIES. TRANSFERRING / AWAITING_PROOF: just count
		// retries; receiver is responsible for re-REQing.
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
		         elapsed > window_timeout_ms * Type::Resource::MAX_RETRIES) {
			NOTICEF("Resource: transfer timeout, FAILED hash=%s",
			        d._hash.toHex().c_str());
			cancel();
		}
	}
	else {
		// Receiver. Re-request the current window if we've been waiting
		// too long; FAIL if MAX_RETRIES rounds have been exhausted.
		if (d._status == Type::Resource::TRANSFERRING && elapsed > window_timeout_ms) {
			if (d._retries_left > 0) {
				d._retries_left--;
				DEBUGF("Resource: REQ retry (%u left)", (unsigned)d._retries_left);
				// outstanding_parts is reset by send_part_request itself
				d._outstanding_parts = 0;
				send_part_request();
			}
			else {
				NOTICEF("Resource: receive timeout, FAILED hash=%s",
				        d._hash.toHex().c_str());
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
	// once assembly completes; that hookup lands in step 7 along with the
	// resource_concluded callback wiring.
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

