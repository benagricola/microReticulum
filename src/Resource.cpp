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
	const Bytes encrypted = d._link.encrypt(salted);
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

void Resource::cancel() {
}

/*
:returns: The current progress of the resource transfer as a *float* between 0.0 and 1.0.
*/
float Resource::get_progress() const {
/*
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
	return 0.0;
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
    //return "<"+RNS.hexrep(self.hash,delimit=False)+"/"+RNS.hexrep(self.link.link_id,delimit=False)+">"
	//return "{Resource:" + _object->_hash.toHex() + "}";
	return "{Resource: unknown}";
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

// setters

