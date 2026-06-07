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

#include "Log.h"
#include "Bytes.h"
#include "Type.h"
#include "Cryptography/Hashes.h"
#include "Cryptography/Ed25519.h"
#include "Cryptography/X25519.h"
#include "Cryptography/Token.h"
#include "Utilities/Memory.h"

#include <map>
#include <string>
#include <memory>
#include <cassert>

namespace RNS {

	class Destination;
	class Packet;

	class Identity {

	private:
		class IdentityEntry {
		public:
			IdentityEntry(double timestamp, const Bytes& packet_hash, const Bytes& public_key, const Bytes& app_data, double last_used = 0) :
				_timestamp(timestamp),
				_packet_hash(packet_hash),
				_public_key(public_key),
				_app_data(app_data),
				_last_used(last_used)
			{
			}
		public:
			// _timestamp is the last-announce/learned time (overwritten on every
			// announce by remember()). _last_used is the refresh-on-use (LRU)
			// marker, mirroring upstream known_destinations[dest][4]:
			//   >0  last-use timestamp (set by recall() on a real use)
			//    0  learned-but-never-used
			//   -1  retained/pinned, never evicted
			double _timestamp = 0;
			Bytes _packet_hash;
			Bytes _public_key;
			Bytes _app_data;
			double _last_used = 0;
		};
		//using IdentityTable = std::map<Bytes, IdentityEntry>;
		using IdentityTable = std::map<Bytes, IdentityEntry, std::less<Bytes>, Utilities::Memory::ContainerAllocator<std::pair<const Bytes, IdentityEntry>>>;

	private:
		static IdentityTable _known_destinations;
		static bool _saving_known_destinations;
		// Set true whenever _known_destinations is mutated (remember()).
		// Checked by save_known_destinations() to skip no-op writes when
		// the cache hasn't changed since the last flush. Lets the
		// firmware run save_known_destinations() on a tight (~60 s)
		// interval cheaply, so an unplanned reboot (watchdog, panic)
		// doesn't drop announces learned in the prior hour.
		static bool _known_destinations_dirty;
		// CBA
		static uint16_t _known_destinations_maxsize;

	public:
		Identity(bool create_keys = true);
		Identity(Type::NoneConstructor none) {
			MEMF("Identity NONE object created, this: %p, data: %p", (void*)this, (void*)_object.get());
		}
		Identity(const Identity& identity) : _object(identity._object) {
			MEMF("Identity object copy created, this: %p, data: %p", (void*)this, (void*)_object.get());
		}
		virtual ~Identity() {
			MEMF("Identity object destroyed, this: %p, data: %p", (void*)this, (void*)_object.get());
		}

		inline Identity& operator = (const Identity& identity) {
			_object = identity._object;
			MEMF("Identity object copy created by assignment, this: %p, data: %p", (void*)this, (void*)_object.get());
			return *this;
		}
		inline operator bool() const {
			return _object.get() != nullptr;
		}
		inline bool operator < (const Identity& identity) const {
			return _object.get() < identity._object.get();
		}

	public:
		void createKeys();

		/*
		:returns: The private key as *bytes*
		*/
		inline const Bytes get_private_key() const {
			assert(_object);
			return _object->_prv_bytes + _object->_sig_prv_bytes;
		}
		/*
		:returns: The public key as *bytes*
		*/
		inline const Bytes get_public_key() const {
			assert(_object);
			return _object->_pub_bytes + _object->_sig_pub_bytes;
		}
		bool load_private_key(const Bytes& prv_bytes);
		void load_public_key(const Bytes& pub_bytes);
		inline void update_hashes() {
			assert(_object);
			_object->_hash = truncated_hash(get_public_key());
			TRACEF("Identity::update_hashes: hash: %s", _object->_hash.toHex().c_str());
			_object->_hexhash = _object->_hash.toHex();
		};
		bool load(const char* path);
		bool to_file(const char* path);

		inline const Bytes& get_salt() const { assert(_object); return _object->_hash; }
		inline const Bytes get_context() const { return {Bytes::NONE}; }

		const Bytes encrypt(const Bytes& plaintext) const;
		const Bytes decrypt(const Bytes& ciphertext_token) const;
		const Bytes sign(const Bytes& message) const;
		bool validate(const Bytes& signature, const Bytes& message) const;
		// CBA following default for reference value requires inclusiion of header
		//void prove(const Packet& packet, const Destination& destination = {Type::NONE}) const;
		void prove(const Packet& packet, const Destination& destination) const;
		void prove(const Packet& packet) const;

		static const Identity from_file(const char* path);
		static void remember(const Bytes& packet_hash, const Bytes& destination_hash, const Bytes& public_key, const Bytes& app_data = {Bytes::NONE});
		// no_use=true mirrors upstream recall(..., _no_use=True): the recall is
		// internal housekeeping (announce processing/validation, link-proof key
		// lookup, blackhole checks) and must NOT refresh the entry's LRU
		// last-used marker, otherwise the announce flood self-refreshes every
		// entry and LRU eviction is defeated.
		static Identity recall(const Bytes& destination_hash, bool no_use = false);
		// Pin a destination against LRU eviction (sets the _last_used sentinel to
		// -1). Mirrors upstream _retain_destination_data; the firmware LXMF layer
		// calls this when an outbound message is confirmed DELIVERED so a contact
		// we actually talk to survives the known-destinations churn. Returns false
		// if the destination isn't in the cache (nothing to pin yet).
		static bool retain_destination(const Bytes& destination_hash);
		static Bytes recall_app_data(const Bytes& destination_hash);
		static bool save_known_destinations();
		// Force the next save_known_destinations() to actually write (bypass the
		// not-dirty fast-path). Diagnostics only — lets a probe measure the
		// full-blob persist cost on demand instead of waiting for the hourly job.
		static void mark_known_destinations_dirty() { _known_destinations_dirty = true; }
		static void load_known_destinations();
		// CBA
		static void cull_known_destinations();

		/*
		Get a SHA-256 hash of passed data.

		:param data: Data to be hashed as *bytes*.
		:returns: SHA-256 hash as *bytes*
		*/
		static inline const Bytes full_hash(const Bytes& data) {
			return Cryptography::sha256(data);
		}

		/*
		Get a truncated SHA-256 hash of passed data.

		:param data: Data to be hashed as *bytes*.
		:returns: Truncated SHA-256 hash as *bytes*
		*/
		static inline const Bytes truncated_hash(const Bytes& data) {
			//p return Identity.full_hash(data)[:(Identity.TRUNCATED_HASHLENGTH//8)]
			return full_hash(data).left(Type::Identity::TRUNCATED_HASHLENGTH/8);
		}

		/*
		Get a random SHA-256 hash.

		:param data: Data to be hashed as *bytes*.
		:returns: Truncated SHA-256 hash of random data as *bytes*
		*/
		static inline const Bytes get_random_hash() {
			return truncated_hash(Cryptography::random(Type::Identity::TRUNCATED_HASHLENGTH/8));
		}

		static bool validate_announce(const Packet& packet);
		static void persist_data();
		static void exit_handler();

		// getters/setters
		inline const Bytes& encryptionPrivateKey() const { assert(_object); return _object->_prv_bytes; }
		inline const Bytes& signingPrivateKey() const { assert(_object); return _object->_sig_prv_bytes; }
		inline const Bytes& encryptionPublicKey() const { assert(_object); return _object->_pub_bytes; }
		inline const Bytes& signingPublicKey() const { assert(_object); return _object->_sig_pub_bytes; }
		inline const Bytes& hash() const { assert(_object); return _object->_hash; }
		inline std::string hexhash() const { assert(_object); return _object->_hexhash; }
		inline const Bytes& app_data() const { assert(_object); return _object->_app_data; }
		inline void app_data(const Bytes& app_data) { assert(_object); _object->_app_data = app_data; }
		inline const Cryptography::X25519PrivateKey::Ptr prv() const { assert(_object); return _object->_prv; }
		inline const Cryptography::Ed25519PrivateKey::Ptr sig_prv() const { assert(_object); return _object->_sig_prv; }
		inline const Cryptography::X25519PublicKey::Ptr pub() const { assert(_object); return _object->_pub; }
		inline const Cryptography::Ed25519PublicKey::Ptr sig_pub() const { assert(_object); return _object->_sig_pub; }
		inline static uint16_t known_destinations_maxsize() { return _known_destinations_maxsize; }
		inline static void known_destinations_maxsize(uint16_t known_destinations_maxsize) { _known_destinations_maxsize = known_destinations_maxsize; }
		inline static size_t known_destinations_count() { return _known_destinations.size(); }

		inline std::string toString() const { if (!_object) return ""; return "{Identity:" + _object->_hash.toHex() + "}"; }

	private:
		class Object {
		public:
			Object() { MEMF("Identity::Data object created, this: %p", (void*)this); }
			virtual ~Object() { MEMF("Identity::Data object destroyed, this: %p", (void*)this); }
		private:

			Cryptography::X25519PrivateKey::Ptr _prv;
			Bytes _prv_bytes;

			Cryptography::Ed25519PrivateKey::Ptr _sig_prv;
			Bytes _sig_prv_bytes;

			Cryptography::X25519PublicKey::Ptr _pub;
			Bytes _pub_bytes;

			Cryptography::Ed25519PublicKey::Ptr _sig_pub;
			Bytes _sig_pub_bytes;

			Bytes _hash;
			std::string _hexhash;

			Bytes _app_data;

		friend class Identity;
		};
		std::shared_ptr<Object> _object;

	// CBA For access to private static members by Transport class
	friend class Transport;
	};

}