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

#pragma once

#include "Destination.h"
#include "Type.h"

#include <memory>
#include <cassert>

namespace RNS {

	class ResourceData;
	class Packet;
	class Destination;
	class Link;
	class Resource;
	class ResourceAdvertisement;   // forward-declared so Resource's member
	                               // signatures resolve to this class
	                               // rather than the same-named namespace
	                               // at RNS::Type::Resource::ResourceAdvertisement.

	class Resource {

	public:
		class Callbacks {
		public:
			// CBA std::function apparently not implemented in NRF52 framework
			//typedef std::function<void(const Resource& resource)> concluded;
			using concluded = void(*)(const Resource& resource);
			using progress = void(*)(const Resource& resource);
		public:
			concluded _concluded = nullptr;
			progress _progress = nullptr;
		friend class Resource;
		};

	public:
		Resource(Type::NoneConstructor none) {
			MEM("Resource NONE object created");
		}
		Resource(const Resource& resource) : _object(resource._object) {
			MEM("Resource object copy created");
		}
		//Resource(const Link& link = {Type::NONE});
		Resource(const Bytes& data, const Link& link, const Bytes& request_id, bool is_response, double timeout);
		Resource(const Bytes& data, const Link& link, bool advertise = true, bool auto_compress = true, Callbacks::concluded callback = nullptr, Callbacks::progress progress_callback = nullptr, double timeout = 0.0, int segment_index = 1, const Bytes& original_hash = {Type::NONE}, const Bytes& request_id = {Type::NONE}, bool is_response = false);
		virtual ~Resource(){
			MEM("Resource object destroyed");
		}

		Resource& operator = (const Resource& resource) {
			_object = resource._object;
			return *this;
		}
		operator bool() const {
			return _object.get() != nullptr;
		}
		bool operator < (const Resource& resource) const {
			return _object.get() < resource._object.get();
			//return _object->_hash < resource._object->_hash;
		}

	public:
		// Receiver-side factory. Builds a Resource in receive mode against
		// the given Link: allocates a ResourceBuffer sized to the
		// advertisement, seeds the hashmap with the ADV's first-segment
		// map_hashes, sets initiator=false / status=TRANSFERRING, and
		// returns the handle for the caller to register with
		// link.register_incoming_resource. Returns a NONE-Resource on
		// buffer allocation failure (flash quota / out of memory).
		static Resource accept(const ResourceAdvertisement& adv,
		                       const Link& link,
		                       Callbacks::concluded concluded = nullptr,
		                       Callbacks::progress progress = nullptr);

		// Receiver: send a RESOURCE_REQ packet asking for the next window
		// of parts we haven't yet received. Called once after accept (the
		// initial request), then again after each window completes.
		void send_part_request();

		// Receiver: ingest an incoming RESOURCE part packet. Computes the
		// part's map_hash, locates the corresponding slot, writes data
		// into the ResourceBuffer at part_index*sdu. If the window is now
		// fully satisfied, fires the next REQ; if all parts have arrived,
		// triggers assembly + PRF emission. Silently ignores parts whose
		// map_hash doesn't match anything we expect.
		void on_part(const Packet& part_packet);

		// Sender-only: ingest an incoming RESOURCE_REQ body and send the
		// requested parts as RESOURCE packets. Body layout matches
		// Resource.py:931-979: [exhausted][last_map_hash if exhausted]
		// [resource_hash 16B][requested_map_hashes 4*n]. If exhausted is
		// set, also emit the next hashmap segment via _send_hmu.
		void on_request(const Bytes& body);

		// Receiver: ingest an incoming RESOURCE_HMU body (16-byte hash
		// prefix + msgpack[segment, hashmap_bytes]). Extends our
		// _map_hashes vector with the additional segment's map_hashes.
		void on_hashmap_update(const Bytes& body);

		// Sender-only: handle an incoming RESOURCE_PRF (32 B SHA-256).
		// Verifies against _expected_proof, transitions to COMPLETE or
		// CORRUPT, fires the conclusion callback.
		void on_proof(const Bytes& proof);

		// Receiver: incoming RESOURCE_ICL (sender abandoned). Releases
		// state; fires concluded callback with FAILED status.
		void on_initiator_cancel(const Bytes& sender_hash);

		// Sender: incoming RESOURCE_RCL (receiver refused/abandoned).
		// Releases state; fires concluded callback with FAILED status.
		void on_receiver_cancel(const Bytes& receiver_hash);

		// Periodic-tick watchdog. The caller (Link / firmware main loop)
		// invokes this every loop pass with the current OS::ltime(). The
		// resource checks how long it's been since _last_activity_ms and
		// retries / fails as appropriate, with up to MAX_RETRIES rounds
		// for parts (receiver) or MAX_ADV_RETRIES re-advertisements
		// (sender). Once status is COMPLETE / FAILED / CORRUPT this is
		// a no-op.
		void tick(uint64_t now_ms);

		// Computed plaintext after assemble succeeds (receiver side).
		// Equivalent to data() for senders. Empty before assembly.
		const Bytes& plaintext() const;

	private:
		// Sender-side pipeline (step 5):
		//  * encrypt the plaintext via the parent Link
		//  * compute resource_hash, random_hash, expected_proof
		//  * slice into parts; compute map_hash per part; concat into the
		//    full hashmap blob
		// Returns false on Link-MDU-not-known or size-cap violation; the
		// constructor leaves status=NONE in that case so the caller (LXMF
		// dispatch) can choose how to handle a build failure.
		bool _build_outgoing(uint16_t link_mdu);

		// Send the RESOURCE_ADV packet plus any follow-up RESOURCE_HMU
		// packets (one per hashmap segment beyond the first), register
		// the resource with the Link, transition to ADVERTISED.
		void _send_advertisement();

		// Emit a single RESOURCE_HMU packet for segment >= 1 of the
		// hashmap. Called by _send_advertisement() proactively and by
		// the REQ handler reactively (step 8) when the receiver asks
		// for more.
		void _send_hmu(uint8_t segment_index);

		// Receiver-only: called from on_part when all parts have arrived.
		// Hashes the assembled buffer + random_hash, compares to the
		// advertised _hash, then decrypts via the Link, strips the
		// random_hash prefix, stores the plaintext in _plaintext for
		// callback retrieval, fires the concluded callback, sends PRF.
		void _assemble_and_deliver();

		// Receiver-only: emit the RESOURCE_PRF packet so the sender
		// can transition to COMPLETE.
		void _send_proof();

	public:
//p def hashmap_update_packet(self, plaintext):
//p def hashmap_update(self, segment, hashmap):
//p def get_map_hash(self, data):
//p def advertise(self):
//p def __advertise_job(self):
//p def watchdog_job(self):
//p def __watchdog_job(self):
//p def assemble(self):
//p def prove(self):
		void validate_proof(const Bytes& proof_data);
//p def receive_part(self, packet):
//p def request_next(self):
//p def request(self, request_data):
		void cancel();
//p def set_callback(self, callback):
//p def progress_callback(self, callback):
		float get_progress() const;
//p def get_transfer_size(self):
//p def get_data_size(self):
//p def get_parts(self):
//p def get_segments(self):
//p def get_hash(self):
//p def is_compressed(self):
		void set_concluded_callback(Callbacks::concluded callback);
		void set_progress_callback(Callbacks::progress callback);

		std::string toString() const;

		// getters
		const Bytes& hash() const;
		const Bytes& request_id() const;
		const Bytes& data() const;
		const Type::Resource::status status() const;
		const size_t size() const;
		const size_t total_size() const;
		// The underlying Link this resource transfers over. Used by callers
		// of resource_concluded_callback to identify which link the now-
		// terminal resource belonged to (Link is otherwise not in the
		// callback parameter list).
		const Link& link() const;

		// setters

	protected:
		std::shared_ptr<ResourceData> _object;

	};


	// Wire form of a RESOURCE_ADV packet body. The msgpack dict layout is
	// dictated by interop with stock RNS (see RNS/Resource.py:1281-1307,
	// 1341-1380). Field key letters and the f-flag bit positions are not
	// negotiable — peers identify fields by exact key.
	class ResourceAdvertisement {
	public:
		// Bit positions in the `f` flag byte
		static const uint8_t FLAG_ENCRYPTED    = 0x01;  // bit 0
		static const uint8_t FLAG_COMPRESSED   = 0x02;  // bit 1
		static const uint8_t FLAG_SPLIT        = 0x04;  // bit 2
		static const uint8_t FLAG_IS_REQUEST   = 0x08;  // bit 3
		static const uint8_t FLAG_IS_RESPONSE  = 0x10;  // bit 4
		static const uint8_t FLAG_HAS_METADATA = 0x20;  // bit 5

		ResourceAdvertisement() = default;

		// Serialize to a msgpack body suitable for use as RESOURCE_ADV packet
		// data. Field order matches Python (t,d,n,h,r,o,i,l,q,f,m) so wire
		// captures look identical to reference traffic, although peers don't
		// rely on order.
		Bytes pack() const;

		// Parse a msgpack body into an advertisement. Returns false (and
		// leaves the object in an indeterminate state) on malformed input or
		// missing required keys.
		bool unpack(const Bytes& body);

		// Field accessors
		uint32_t       transfer_size()  const { return _t; }
		uint32_t       data_size()      const { return _d; }
		uint16_t       parts()          const { return _n; }
		const Bytes&   hash()           const { return _h; }
		const Bytes&   random_hash()    const { return _r; }
		const Bytes&   original_hash()  const { return _o; }
		uint8_t        segment_index()  const { return _i; }
		uint8_t        total_segments() const { return _l; }
		const Bytes&   request_id()     const { return _q; }
		uint8_t        flags()          const { return _f; }
		const Bytes&   hashmap()        const { return _m; }

		bool encrypted()    const { return (_f & FLAG_ENCRYPTED)    != 0; }
		bool compressed()   const { return (_f & FLAG_COMPRESSED)   != 0; }
		bool split()        const { return (_f & FLAG_SPLIT)        != 0; }
		bool is_request()   const { return (_f & FLAG_IS_REQUEST)   != 0; }
		bool is_response()  const { return (_f & FLAG_IS_RESPONSE)  != 0; }
		bool has_metadata() const { return (_f & FLAG_HAS_METADATA) != 0; }

		// Mutators (used by Resource sender to populate before pack())
		void set_transfer_size(uint32_t t)        { _t = t; }
		void set_data_size(uint32_t d)            { _d = d; }
		void set_parts(uint16_t n)                { _n = n; }
		void set_hash(const Bytes& h)             { _h = h; }
		void set_random_hash(const Bytes& r)      { _r = r; }
		void set_original_hash(const Bytes& o)    { _o = o; }
		void set_segment_index(uint8_t i)         { _i = i; }
		void set_total_segments(uint8_t l)        { _l = l; }
		void set_request_id(const Bytes& q)       { _q = q; }
		void set_flags(uint8_t f)                 { _f = f; }
		void set_hashmap(const Bytes& m)          { _m = m; }

	private:
		uint32_t _t = 0;   // transfer size (on-wire, after encryption)
		uint32_t _d = 0;   // data size (uncompressed; equal to _t since c=0)
		uint16_t _n = 0;   // number of parts
		Bytes    _h;       // 16 B resource hash
		Bytes    _r;       // 4  B random salt
		Bytes    _o;       // 16 B original (first-segment) hash; equals _h
		uint8_t  _i = 1;   // segment index (always 1 in this port)
		uint8_t  _l = 1;   // total segments (always 1 in this port)
		Bytes    _q;       // empty (nil-on-wire) for non-request resources
		uint8_t  _f = 0;   // flag byte (see FLAG_* above)
		Bytes    _m;       // hashmap bytes (n * 4)
	};

}
