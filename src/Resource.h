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
	    //p static def accept(advertisement_packet, callback=None, progress_callback = None, request_id = None):

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
