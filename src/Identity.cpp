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

#include "Identity.h"

#include "Reticulum.h"
#include "Transport.h"
#include "Packet.h"
#include "Log.h"
#include "Utilities/OS.h"
#include "Cryptography/Ed25519.h"
#include "Cryptography/X25519.h"
#include "Cryptography/HKDF.h"
#include "Cryptography/Token.h"
#include "Cryptography/Random.h"

#include <algorithm>
#include <string.h>

using namespace RNS;

// PATCH-INBOUND-RATCHET-V1
// Provider hook: returns the index-th (0=newest) ratchet privkey
// for the identity being decrypted to. Wired from the LXMF gateway.
typedef bool (*inbound_ratchet_privkey_fn)(const uint8_t* identity_hash, size_t index, uint8_t* out_privkey_32);
static inbound_ratchet_privkey_fn _lxmf_inbound_ratchet_provider = nullptr;
extern "C" void rns_set_inbound_ratchet_provider(inbound_ratchet_privkey_fn fn) {
    _lxmf_inbound_ratchet_provider = fn;
}
using namespace RNS::Type::Identity;
using namespace RNS::Cryptography;
using namespace RNS::Utilities;

#ifndef RNS_KNOWN_DESTINATIONS_MAX
#define RNS_KNOWN_DESTINATIONS_MAX 100
#endif

// Flash persist-tier geometry for the known-destinations store (mirrors the
// path store). Eight 24 KB segments = 192 KB ceiling, ample for the runtime cap
// (set to URTN_PATH_TABLE_MAX_RECS by the firmware) of ~300-byte records.
#ifndef RNS_KNOWN_DEST_SEGMENT_SIZE
#define RNS_KNOWN_DEST_SEGMENT_SIZE 24576
#endif
#ifndef RNS_KNOWN_DEST_SEGMENT_COUNT
#define RNS_KNOWN_DEST_SEGMENT_COUNT 8
#endif

// The known-destinations cache: a PSRAM front (always) + an optional flash
// persist tier (RNS_PERSIST_KNOWN_DESTS, enabled at init() when a filesystem is
// present). _known_destinations is the typed Bytes->IdentityEntry view over it.
/*static*/ Identity::KnownDestStore Identity::_known_dest_store(RNS_KNOWN_DEST_SEGMENT_SIZE, RNS_KNOWN_DEST_SEGMENT_COUNT);
/*static*/ Identity::KnownDestTable Identity::_known_destinations(Identity::_known_dest_store);
// CBA
// CBA ACCUMULATES
/*static*/ uint16_t Identity::_known_destinations_maxsize = RNS_KNOWN_DESTINATIONS_MAX;

// Legacy known_destinations blob format constants — read once by the one-time
// migration in load_known_destinations() that imports the old single-file cache
// into the per-record store. The format is no longer written.
namespace {
constexpr uint32_t KD_MAGIC   = 0xC0DEC0DE;
// v2 added the LRU last_used marker (int64 ms; -1000 sentinel = retained) per
// entry. v1 files (no marker) load with last_used defaulting to 0.
constexpr uint32_t KD_VERSION = 2;
} // anonymous namespace

Identity::Identity(bool create_keys /*= true*/) : _object(new Object()) {
	if (create_keys) {
		createKeys();
	}
	MEMF("Identity object created, this: %p, data: %p", (void*)this, (void*)_object.get());
}

void Identity::createKeys() {
	assert(_object);

	// CRYPTO: create encryption private keys
	_object->_prv           = Cryptography::X25519PrivateKey::generate();
	_object->_prv_bytes     = _object->_prv->private_bytes();
	//TRACEF("Identity::createKeys: prv bytes:     %s", _object->_prv_bytes.toHex().c_str());

	// CRYPTO: create signature private keys
	_object->_sig_prv       = Cryptography::Ed25519PrivateKey::generate();
	_object->_sig_prv_bytes = _object->_sig_prv->private_bytes();
	//TRACEF("Identity::createKeys: sig prv bytes: %s", _object->_sig_prv_bytes.toHex().c_str());

	// CRYPTO: create encryption public keys
	_object->_pub           = _object->_prv->public_key();
	_object->_pub_bytes     = _object->_pub->public_bytes();
	//TRACEF("Identity::createKeys: pub bytes:     %s", _object->_pub_bytes.toHex().c_str());

	// CRYPTO: create signature public keys
	_object->_sig_pub       = _object->_sig_prv->public_key();
	_object->_sig_pub_bytes = _object->_sig_pub->public_bytes();
	//TRACEF("Identity::createKeys: sig pub bytes: %s", _object->_sig_pub_bytes.toHex().c_str());

	update_hashes();

	VERBOSEF("Identity keys created for %s", _object->_hash.toHex().c_str());
}

/*
Load a private key into the instance.

:param prv_bytes: The private key as *bytes*.
:returns: True if the key was loaded, otherwise False.
*/
bool Identity::load_private_key(const Bytes& prv_bytes) {
	assert(_object);

	try {

		//p self.prv_bytes     = prv_bytes[:Identity.KEYSIZE//8//2]
		_object->_prv_bytes     = prv_bytes.left(Type::Identity::KEYSIZE/8/2);
		_object->_prv           = X25519PrivateKey::from_private_bytes(_object->_prv_bytes);
		//TRACEF("Identity::load_private_key: prv bytes:     %s", _object->_prv_bytes.toHex().c_str());

		//p self.sig_prv_bytes = prv_bytes[Identity.KEYSIZE//8//2:]
		_object->_sig_prv_bytes = prv_bytes.mid(Type::Identity::KEYSIZE/8/2);
		_object->_sig_prv       = Ed25519PrivateKey::from_private_bytes(_object->_sig_prv_bytes);
		//TRACEF("Identity::load_private_key: sig prv bytes: %s", _object->_sig_prv_bytes.toHex().c_str());

		_object->_pub           = _object->_prv->public_key();
		_object->_pub_bytes     = _object->_pub->public_bytes();
		//TRACEF("Identity::load_private_key: pub bytes:     %s", _object->_pub_bytes.toHex().c_str());

		_object->_sig_pub       = _object->_sig_prv->public_key();
		_object->_sig_pub_bytes = _object->_sig_pub->public_bytes();
		//TRACEF("Identity::load_private_key: sig pub bytes: %s", _object->_sig_pub_bytes.toHex().c_str());

		update_hashes();

		return true;
	}
	catch (const std::exception& e) {
		//p raise e
		ERROR("Failed to load identity key");
		ERRORF("The contained exception was: %s", e.what());
		return false;
	}
}

/*
Load a public key into the instance.

:param pub_bytes: The public key as *bytes*.
:returns: True if the key was loaded, otherwise False.
*/
void Identity::load_public_key(const Bytes& pub_bytes) {
	assert(_object);

	try {

		//_pub_bytes     = pub_bytes[:Identity.KEYSIZE//8//2]
		_object->_pub_bytes     = pub_bytes.left(Type::Identity::KEYSIZE/8/2);
		//TRACEF("Identity::load_public_key: pub bytes:     ", _object->_pub_bytes.toHex().c_str());

		//_sig_pub_bytes = pub_bytes[Identity.KEYSIZE//8//2:]
		_object->_sig_pub_bytes = pub_bytes.mid(Type::Identity::KEYSIZE/8/2);
		//TRACEF("Identity::load_public_key: sig pub bytes: ", _object->_sig_pub_bytes.toHex().c_str());

		_object->_pub           = X25519PublicKey::from_public_bytes(_object->_pub_bytes);
		_object->_sig_pub       = Ed25519PublicKey::from_public_bytes(_object->_sig_pub_bytes);

		update_hashes();
	}
	catch (const std::exception& e) {
		ERRORF("Error while loading public key, the contained exception was: %s", e.what());
	}
}

bool Identity::load(const char* path) {
	TRACE("Reading identity key from storage...");
#if defined(RNS_USE_FS)
	try {
		Bytes prv_bytes;
		if (OS::read_file(path, prv_bytes) > 0) {
			return load_private_key(prv_bytes);
		}
		else {
			return false;
		}
	}
	catch (const std::exception& e) {
		ERRORF("Error while loading identity from %s", path);
		ERRORF("The contained exception was: %s", e.what());
	}
#endif
	return false;
}

/*
Saves the identity to a file. This will write the private key to disk,
and anyone with access to this file will be able to decrypt all
communication for the identity. Be very careful with this method.

:param path: The full path specifying where to save the identity.
:returns: True if the file was saved, otherwise False.
*/
bool Identity::to_file(const char* path) {
	TRACE("Writing identity key to storage...");
#if defined(RNS_USE_FS)
	try {
		return (OS::write_file(path, get_private_key()) == get_private_key().size());
	}
	catch (const std::exception& e) {
		ERRORF("Error while saving identity to %s", path);
		ERRORF("The contained exception was: %s", e.what());
	}
#endif
	return false;
}


/*
Create a new :ref:`RNS.Identity<api-identity>` instance from a file.
Can be used to load previously created and saved identities into Reticulum.

:param path: The full path to the saved :ref:`RNS.Identity<api-identity>` data
:returns: A :ref:`RNS.Identity<api-identity>` instance, or *None* if the loaded data was invalid.
*/
/*static*/ const Identity Identity::from_file(const char* path) {
	Identity identity(false);
	if (identity.load(path)) {
		return identity;
	}
	return {Type::NONE};
}

/*static*/ void Identity::remember(const Bytes& packet_hash, const Bytes& destination_hash, const Bytes& public_key, const Bytes& app_data /*= {Bytes::NONE}*/) {
	if (public_key.size() != Type::Identity::KEYSIZE/8) {
		throw std::invalid_argument("Can't remember " + destination_hash.toHex() + ", the public key size of " + std::to_string(public_key.size()) + " is not valid.");
	}
	else {
		//p _known_destinations[destination_hash] = {OS::time(), packet_hash, public_key, app_data};
		// CBA ACCUMULATES
		try {
			// insert_or_assign (NOT insert) — std::map::insert leaves the
			// existing value untouched if the key already exists, which
			// means subsequent announces from a known peer never refresh
			// the stored timestamp. cull_known_destinations sorts by
			// timestamp and would then evict actively-announcing peers
			// first because their stored ts stayed pinned to first-heard,
			// producing the "AnnounceLog has the entry but Identity::recall
			// returns empty" divergence. Overwrite on every announce.
			// Preserve the LRU last-used marker across re-announces, mirroring
			// upstream remember() which only overwrites [0..3] for an existing
			// entry and leaves [4] (last_used / retained) intact. A fresh entry
			// starts at 0 (learned-but-never-used).
			double last_used = 0;
			bool genuine = true;   // new key / changed identity ⇒ persist; else front-only
			IdentityEntry existing;
			if (_known_destinations.get(destination_hash, existing)) {
				last_used = existing._last_used;
				// A re-announce from a known peer usually only bumps the timestamp;
				// the durable identity (public key + app_data) is unchanged. That is
				// a volatile touch — keep it in the PSRAM front (put_front) and out
				// of the flash tier, exactly like the path store's refresh-on-use.
				// Persisting every announce would otherwise hammer flash under the
				// backbone feed. The persist tier records only genuine changes.
				genuine = (existing._public_key != public_key) || (existing._app_data != app_data);
			}
			IdentityEntry updated{OS::time(), packet_hash, public_key, app_data, last_used};
			if (genuine)
				_known_destinations.put(destination_hash, updated);        // front + flash
			else
				_known_destinations.put_front(destination_hash, updated);  // front only
			// CBA IMMEDIATE CULL
			cull_known_destinations();
		}
		catch (const std::bad_alloc&) {
			ERRORF("remember: bad_alloc - OUT OF MEMORY, identity not stored for %s", destination_hash.toHex().c_str());
		}
		catch (const std::exception& e) {
			ERRORF("remember: exception storing identity: %s", e.what());
		}
	}
}

/*
Retain (pin) a destination so it is never evicted by cull_known_destinations.

Mirrors upstream Identity._retain_destination_data() (Identity.py:267-272), which
the LXMF router calls once an outbound message reaches DELIVERED so a contact's
identity/key survives table churn. Sets the LRU marker to the -1 sentinel, which
recall() leaves untouched and the cull treats as never-a-candidate.
*/
/*static*/ bool Identity::retain_destination(const Bytes& destination_hash) {
	IdentityEntry entry;
	if (_known_destinations.get(destination_hash, entry)) {
		if (!(entry._last_used < 0)) {
			entry._last_used = -1;
			// Pinning is a durable state change (a contact we've delivered to),
			// so write through to the persist tier — not put_front.
			_known_destinations.put(destination_hash, entry);
		}
		return true;
	}
	return false;
}

/*
Recall identity for a destination hash.

:param destination_hash: Destination hash as *bytes*.
:returns: An :ref:`RNS.Identity<api-identity>` instance that can be used to create an outgoing :ref:`RNS.Destination<api-destination>`, or *None* if the destination is unknown.
*/
/*static*/ Identity Identity::recall(const Bytes& destination_hash, bool no_use /*= false*/) {
	TRACE("Identity::recall...");
	IdentityEntry identity_data;
	if (_known_destinations.get(destination_hash, identity_data)) {
		TRACEF("Identity::recall: Found identity entry for destination %s", destination_hash.toHex().c_str());
		// Refresh-on-use (LRU), mirroring upstream _used_destination_data():
		// mark this destination used now unless the recall is internal
		// housekeeping (no_use) or the entry is retained/pinned (_last_used<0).
		// A volatile touch, so front-only (put_front) — it must NOT churn the
		// flash persist tier on every use (the announce feed alone would).
		if (!no_use && !(identity_data._last_used < 0)) {
			identity_data._last_used = OS::time();
			_known_destinations.put_front(destination_hash, identity_data);
		}
		Identity identity(false);
		identity.load_public_key(identity_data._public_key);
		identity.app_data(identity_data._app_data);
		return identity;
	}
	else {
		TRACEF("Identity::recall: Unable to find identity entry for destination %s, performing destination lookup...", destination_hash.toHex().c_str());
		Destination registered_destination(Transport::find_destination_from_hash(destination_hash));
		if (registered_destination) {
			TRACEF("Identity::recall: Found destination %s", destination_hash.toHex().c_str());
			// A registered destination need not carry an identity (group/plain
			// types); guard before get_public_key() and fall through to the
			// announce-based recovery below rather than dereferencing NONE.
			if (registered_destination.identity()) {
				Identity identity(false);
				identity.load_public_key(registered_destination.identity().get_public_key());
				identity.app_data({Bytes::NONE});
				return identity;
			}
			TRACEF("Identity::recall: Destination %s has no associated identity", destination_hash.toHex().c_str());
		}
		TRACEF("Identity::recall: Unable to find destination %s", destination_hash.toHex().c_str());

		// The in-RAM identity cache may have evicted this destination under a
		// high-cardinality announce feed even though we still hold a route to
		// it. The path record stores the destination's announce inline (it
		// carries the public key), so recover the identity from there.
		// validate_announce re-verifies the signature + destination-hash binding
		// and re-remember()s the key, so a subsequent recall hits the fast
		// cache path. Makes "has a path => can recall the key" structurally true.
		Packet stored_announce = Transport::path_announce(destination_hash);
		if (stored_announce && validate_announce(stored_announce)) {
			IdentityEntry cached;
			if (_known_destinations.get(destination_hash, cached)) {
				TRACEF("Identity::recall: recovered identity for %s from path-record announce", destination_hash.toHex().c_str());
				Identity identity(false);
				identity.load_public_key(cached._public_key);
				identity.app_data(cached._app_data);
				return identity;
			}
		}

		return {Type::NONE};
	}
}

/*
Recall last heard app_data for a destination hash.

:param destination_hash: Destination hash as *bytes*.
:returns: *Bytes* containing app_data, or *None* if the destination is unknown.
*/
/*static*/ Bytes Identity::recall_app_data(const Bytes& destination_hash) {
	TRACE("Identity::recall_app_data...");
	IdentityEntry identity_data;
	if (_known_destinations.get(destination_hash, identity_data)) {
		TRACEF("Identity::recall_app_data: Found identity entry for destination %s", destination_hash.toHex().c_str());
		return identity_data._app_data;
	}
	else {
		TRACEF("Identity::recall_app_data: Unable to find identity entry for destination %s", destination_hash.toHex().c_str());
		return {Bytes::NONE};
	}
}

/*static*/ void Identity::known_destinations_compact_step() {
	_known_dest_store.compact_step();
}

// One-time import of the legacy single-file known_destinations blob into the
// per-record store. Runs at boot after the store is up; on success the old file
// is deleted so it never imports twice. Returns the number of entries imported.
//
// Legacy wire format:
//   uint32_t magic = 0xC0DEC0DE, uint32_t version (1 or 2), uint16_t count, then
//   per entry: dest_hash (u16 len+bytes), timestamp_ms (u64), pkt_hash, pub_key,
//   app_data (each u16 len+bytes), and (v2+) last_used_ms (signed u64).
static uint16_t migrate_legacy_known_destinations(RNS::Persistence::KnownDestTable& table) {
	using namespace RNS;
	char path[Type::Reticulum::FILEPATH_MAXSIZE];
	snprintf(path, Type::Reticulum::FILEPATH_MAXSIZE, "%s/known_destinations", Reticulum::storagepath());
	if (!OS::file_exists(path)) return 0;
	Bytes buf;
	if (OS::read_file(path, buf) == 0) { OS::remove_file(path); return 0; }

	const uint8_t* p   = buf.data();
	const uint8_t* end = p + buf.size();
	auto need = [&](size_t n) { return (size_t)(end - p) >= n; };
	auto read_u16 = [&]() -> uint16_t { uint16_t v = ((uint16_t)p[0] << 8) | p[1]; p += 2; return v; };
	auto read_u32 = [&]() -> uint32_t {
		uint32_t v = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; p += 4; return v;
	};
	auto read_u64 = [&]() -> uint64_t { uint64_t v = 0; for (int i = 0; i < 8; ++i) v = (v << 8) | p[i]; p += 8; return v; };
	auto read_bytes = [&]() -> Bytes {
		if (!need(2)) return Bytes();
		uint16_t len = read_u16();
		if (!need(len)) return Bytes();
		Bytes b(p, len); p += len; return b;
	};

	uint16_t imported = 0;
	try {
		if (!need(10)) { OS::remove_file(path); return 0; }
		if (read_u32() != KD_MAGIC) { OS::remove_file(path); return 0; }
		uint32_t version = read_u32();
		if (version != 1 && version != KD_VERSION) { OS::remove_file(path); return 0; }
		uint16_t count = read_u16();
		for (uint16_t i = 0; i < count; ++i) {
			Bytes dest_hash = read_bytes();
			if (!need(8)) break;
			uint64_t ts_ms  = read_u64();
			Bytes pkt_hash  = read_bytes();
			Bytes pub_key   = read_bytes();
			Bytes app_data  = read_bytes();
			double last_used = 0;
			if (version >= 2) { if (!need(8)) break; last_used = (double)(int64_t)read_u64() / 1000.0; }
			if (dest_hash.size() != Type::Reticulum::TRUNCATED_HASHLENGTH / 8) continue;
			if (pub_key.size()   != Type::Identity::KEYSIZE / 8) continue;
			table.put(dest_hash, Persistence::IdentityEntry{(double)ts_ms / 1000.0, pkt_hash, pub_key, app_data, last_used});
			imported++;
		}
	}
	catch (const std::exception& e) {
		ERRORF("Identity: legacy known_destinations migration exception: %s", e.what());
	}
	OS::remove_file(path);   // imported (or unparseable) — don't import again
	return imported;
}

/*static*/ void Identity::load_known_destinations() {
	// Bring up the store. init() warms the PSRAM front from the flash persist
	// tier (so a reboot keeps the cache) and enables incremental compaction.
#if defined(RNS_USE_FS) && defined(RNS_PERSIST_KNOWN_DESTS)
	const bool persist = (bool)Utilities::OS::get_filesystem();
#else
	const bool persist = false;
#endif
#if defined(ARDUINO)
	const char* prefix = "/known_dest";
#else
	const char* prefix = "known_dest";
#endif
	_known_dest_store.init(Utilities::OS::get_filesystem(), prefix, persist);

	if (persist) {
		NOTICEF("Identity: known-destinations persist tier ON (%u warm-loaded)", (unsigned)_known_destinations.size());
		const uint16_t migrated = migrate_legacy_known_destinations(_known_destinations);
		if (migrated > 0) {
			NOTICEF("Identity: migrated %u known destinations from the legacy blob", (unsigned)migrated);
		}
	}
	else {
		NOTICE("Identity: known-destinations PSRAM-only (persist tier off)");
	}
}

/*static*/ void Identity::cull_known_destinations() {
	TRACE("Identity::cull_known_destinations()");
	if (_known_destinations.size() > _known_destinations_maxsize) {
		try {
			// Build lightweight (sort-value, key) index to avoid copying full IdentityEntry
			// objects — prevents OOM on heap-constrained devices when the table is full.
			// Evict by least-recently-USED, mirroring upstream clean_known_destinations:
			//   - never evict retained/pinned entries (_last_used == -1)
			//   - order by effective use time: last-use if the entry was ever used
			//     (_last_used > 0), else the learned/last-announce time (_timestamp).
			// Sorting by _timestamp alone (last-announce) wrongly evicted an
			// actively-used destination that announces less often than a chatty
			// backbone node; the use marker fixes that.
			// Collect first, remove after — remove() mutates the store, which
			// would invalidate the iterator if done inline. Iterating the typed
			// view decodes each entry from the PSRAM front (no flash I/O).
			// The sort index is PSRAM-backed (ContainerAllocator): at the 500-entry
			// cap it is ~12 KB, and the component build runs with only ~15-20 KB
			// free INTERNAL SRAM — a default-allocator vector here narrows that
			// margin on every cull and can tip a concurrent allocation into OOM.
			using SortPair = std::pair<double, Bytes>;
			std::vector<SortPair, Memory::ContainerAllocator<SortPair>> sorted_keys;
			sorted_keys.reserve(_known_destinations.size());
			for (auto entry : _known_destinations) {
				if (entry.value._last_used < 0) continue;  // retained/pinned: never a candidate
				double sort_value = (entry.value._last_used > 0) ? entry.value._last_used : entry.value._timestamp;
				sorted_keys.emplace_back(sort_value, entry.key);
			}
			// Sort ascending by effective-use time (least-recently-used first)
			std::sort(sorted_keys.begin(), sorted_keys.end());

			uint16_t count = 0;
			for (const auto& [timestamp, destination_hash] : sorted_keys) {
				TRACEF("Identity::cull_known_destinations: Removing destination %s from known destinations", destination_hash.toHex().c_str());
				if (!_known_destinations.remove(destination_hash)) {
					WARNINGF("Failed to remove destination %s from known destinations", destination_hash.toHex().c_str());
				}
				++count;
				if (_known_destinations.size() <= _known_destinations_maxsize) {
					break;
				}
			}
			DEBUGF("Removed %d path(s) from known destinations", count);
		}
		catch (const std::bad_alloc& e) {
			ERROR("cull_known_destinations: bad_alloc - OUT OF MEMORY building sort index, falling back to single erase");
			// Fallback: no sort index — scan for the single least-recently-used
			// non-retained entry, recording its key, then remove it after the scan
			// (the iterator must not be live across the mutation). Retained
			// (_last_used < 0) entries are skipped so they're never evicted.
			Bytes oldest_key;
			double oldest_value = 0;
			bool found = false;
			for (auto entry : _known_destinations) {
				if (entry.value._last_used < 0) continue;  // retained/pinned
				double value = (entry.value._last_used > 0) ? entry.value._last_used : entry.value._timestamp;
				if (!found || value < oldest_value) {
					oldest_key = entry.key;
					oldest_value = value;
					found = true;
				}
			}
			if (found) _known_destinations.remove(oldest_key);
		}
		catch (const std::exception& e) {
			ERRORF("cull_known_destinations: exception: %s", e.what());
		}
	}
}

/*static*/ bool Identity::validate_announce(const Packet& packet) {
	try {
		if (packet.packet_type() == Type::Packet::ANNOUNCE) {
			// Reject runt/truncated announces before any crypto. A short data
			// buffer yields a short public key, and Ed25519 verify then reads a
			// fixed 32-byte point past the (possibly empty) key buffer — an
			// uncatchable LoadProhibited fault, not a C++ exception the validate()
			// try/catch could absorb. Minimum is the no-ratchet announce layout.
			const size_t min_announce_size = KEYSIZE/8 + NAME_HASH_LENGTH/8 + RANDOM_HASH_LENGTH/8 + SIGLENGTH/8;
			if (packet.data().size() < min_announce_size) {
				DEBUGF("Identity::validate_announce: dropping runt announce (%u < %u bytes)", (unsigned)packet.data().size(), (unsigned)min_announce_size);
				return false;
			}
			Bytes destination_hash = packet.destination_hash();
			//TRACEF("Identity::validate_announce: destination_hash: %s", packet.destination_hash().toHex().c_str());
			Bytes public_key = packet.data().left(KEYSIZE/8);
			//TRACEF("Identity::validate_announce: public_key:       %s", public_key.toHex().c_str());
			Bytes name_hash = packet.data().mid(KEYSIZE/8, NAME_HASH_LENGTH/8);
			//TRACEF("Identity::validate_announce: name_hash:        %s", name_hash.toHex().c_str());
			Bytes random_hash = packet.data().mid(KEYSIZE/8 + NAME_HASH_LENGTH/8, RANDOM_HASH_LENGTH/8);
			//TRACEF("Identity::validate_announce: random_hash:      %s", random_hash.toHex().c_str());
			// PATCH-RATCHET-V1
			const size_t header_len = KEYSIZE/8 + NAME_HASH_LENGTH/8 + RANDOM_HASH_LENGTH/8;
			const bool has_ratchet = (packet.context_flag() == RNS::Type::Packet::FLAG_SET);
			Bytes ratchet;
			if (has_ratchet && packet.data().size() >= header_len + RATCHETSIZE/8) {
				ratchet = packet.data().mid(header_len, RATCHETSIZE/8);
			}
			const size_t sig_offset = header_len + (has_ratchet ? RATCHETSIZE/8 : 0);
			Bytes signature = packet.data().mid(sig_offset, SIGLENGTH/8);
			Bytes app_data;
			if (packet.data().size() > (sig_offset + SIGLENGTH/8)) {
				app_data = packet.data().mid(sig_offset + SIGLENGTH/8);
			}

			Bytes signed_data;
			signed_data << packet.destination_hash() << public_key << name_hash << random_hash;
			if (has_ratchet) signed_data << ratchet;
			signed_data << app_data;

			if (packet.data().size() <= sig_offset + SIGLENGTH/8) {
				app_data.clear();
			}

			Identity announced_identity(false);
			announced_identity.load_public_key(public_key);

			if (announced_identity.pub() && announced_identity.validate(signature, signed_data)) {
				Bytes hash_material = name_hash << announced_identity.hash();
				Bytes expected_hash = full_hash(hash_material).left(Type::Reticulum::TRUNCATED_HASHLENGTH/8);
				//TRACEF("Identity::validate_announce: destination_hash: %s", packet.destination_hash().toHex().c_str());
				//TRACEF("Identity::validate_announce: expected_hash:    %s", expected_hash.toHex().c_str());

				if (packet.destination_hash() == expected_hash) {
					// Check if we already have a public key for this destination
					// and make sure the public key is not different.
					IdentityEntry identity_entry;
					if (_known_destinations.get(packet.destination_hash(), identity_entry)) {
						if (public_key != identity_entry._public_key) {
							// In reality, this should never occur, but in the odd case
							// that someone manages a hash collision, we reject the announce.
							CRITICAL("Received announce with valid signature and destination hash, but announced public key does not match already known public key.");
							CRITICAL("This may indicate an attempt to modify network paths, or a random hash collision. The announce was rejected.");
							return false;
						}
					}

					remember(packet.get_hash(), packet.destination_hash(), public_key, app_data);
					//p del announced_identity

					std::string signal_str;
// TODO
/*
					if packet.rssi != None or packet.snr != None:
						signal_str = " ["
						if packet.rssi != None:
							signal_str += "RSSI "+str(packet.rssi)+"dBm"
							if packet.snr != None:
								signal_str += ", "
						if packet.snr != None:
							signal_str += "SNR "+str(packet.snr)+"dB"
						signal_str += "]"
					else:
						signal_str = ""
*/

					if (packet.transport_id()) {
						TRACEF("Valid announce for %s %d hops away, received via %s on %s%s", packet.destination_hash().toHex().c_str(), packet.hops(), packet.transport_id().toHex().c_str(), packet.receiving_interface().toString().c_str(), signal_str.c_str());
					}
					else {
						TRACEF("Valid announce for %s %d hops away, received on %s%s", packet.destination_hash().toHex().c_str(), packet.hops(), packet.receiving_interface().toString().c_str(), signal_str.c_str());
					}

					return true;
				}
				else {
					NOTICEF("Received invalid announce for %s: Destination mismatch.", packet.destination_hash().toHex().c_str());
					return false;
				}
			}
			else {
				NOTICEF("Received invalid announce for %s: Invalid signature.", packet.destination_hash().toHex().c_str());
				//p del announced_identity
				return false;
			}
		}
	}
	catch (const std::exception& e) {
		ERRORF("Error occurred while validating announce. The contained exception was: %s", e.what());
		return false;
	}
	return false;
}

/*
Encrypts information for the identity.

:param plaintext: The plaintext to be encrypted as *bytes*.
:returns: Ciphertext token as *bytes*.
:raises: *KeyError* if the instance does not hold a public key.
*/
const Bytes Identity::encrypt(const Bytes& plaintext) const {
	assert(_object);
	TRACE("Identity::encrypt: encrypting data...");
	if (!_object->_pub) {
		throw std::runtime_error("Encryption failed because identity does not hold a public key");
	}
	Cryptography::X25519PrivateKey::Ptr ephemeral_key = Cryptography::X25519PrivateKey::generate();
	Bytes ephemeral_pub_bytes = ephemeral_key->public_key()->public_bytes();
	TRACEF("Identity::encrypt: ephemeral public key: %s", ephemeral_pub_bytes.toHex().c_str());

	// CRYPTO: create shared key for key exchange using own public key
	//shared_key = ephemeral_key.exchange(self.pub)
	Bytes shared_key = ephemeral_key->exchange(_object->_pub_bytes);
	TRACEF("Identity::encrypt: shared key:           %s", shared_key.toHex().c_str());

	Bytes derived_key = Cryptography::hkdf(
		DERIVED_KEY_LENGTH,
		shared_key,
		get_salt(),
		get_context()
	);
	TRACEF("Identity::encrypt: derived key:          %s", derived_key.toHex().c_str());

	Cryptography::Token token(derived_key);
	TRACEF("Identity::encrypt: Token encrypting data of length %lu", plaintext.size());
	Bytes ciphertext = token.encrypt(plaintext);

	return ephemeral_pub_bytes + ciphertext;
}


/*
Decrypts information for the identity.

:param ciphertext: The ciphertext to be decrypted as *bytes*.
:returns: Plaintext as *bytes*, or *None* if decryption fails.
:raises: *KeyError* if the instance does not hold a private key.
*/
const Bytes Identity::decrypt(const Bytes& ciphertext_token) const {
	assert(_object);
	TRACE("Identity::decrypt: decrypting data...");
	if (!_object->_prv) {
		throw std::runtime_error("Decryption failed because identity does not hold a private key");
	}
	if (ciphertext_token.size() <= Type::Identity::KEYSIZE/8/2) {
		NOTICEF("Decryption failed because the token size %lu was invalid.", ciphertext_token.size());
		return {Bytes::NONE};
	}
	Bytes peer_pub_bytes = ciphertext_token.left(Type::Identity::KEYSIZE/8/2);
	Bytes ciphertext(ciphertext_token.mid(Type::Identity::KEYSIZE/8/2));

	auto try_decrypt = [&](const Bytes& priv_bytes) -> Bytes {
		try {
			auto prv = Cryptography::X25519PrivateKey::from_private_bytes(priv_bytes);
			Bytes shared_key = prv->exchange(peer_pub_bytes);
			Bytes derived_key = Cryptography::hkdf(
				DERIVED_KEY_LENGTH, shared_key, get_salt(), get_context());
			Cryptography::Token token(derived_key);
			return token.decrypt(ciphertext);
		} catch (...) {
			return Bytes(Bytes::NONE);
		}
	};

	// PATCH-INBOUND-RATCHET-V1: try ratchet privkeys first (newest first).
	if (_lxmf_inbound_ratchet_provider != nullptr) {
		uint8_t prv_buf[Type::Identity::RATCHETSIZE/8];
		for (size_t i = 0; i < 32; ++i) {
			if (!_lxmf_inbound_ratchet_provider(_object->_hash.data(), i, prv_buf)) break;
			Bytes attempt = try_decrypt(Bytes(prv_buf, Type::Identity::RATCHETSIZE/8));
			if (attempt.size() > 0) {
				TRACEF("Identity::decrypt: ratchet privkey #%lu succeeded", (unsigned long)i);
				return attempt;
			}
		}
	}

	Bytes plaintext = try_decrypt(_object->_prv->private_bytes());
	if (plaintext.size() == 0) {
		NOTICEF("Decryption by %s failed: token HMAC was invalid (all ratchet and identity candidates failed)", toString().c_str());
	}
	return plaintext;
}

/*
Signs information by the identity.

:param message: The message to be signed as *bytes*.
:returns: Signature as *bytes*.
:raises: *KeyError* if the instance does not hold a private key.
*/
const Bytes Identity::sign(const Bytes& message) const {
	assert(_object);
	if (!_object->_sig_prv) {
		throw std::runtime_error("Signing failed because identity does not hold a private key");
	}
	try {
		return _object->_sig_prv->sign(message);
	}
	catch (const std::exception& e) {
		ERRORF("The identity %s could not sign the requested message. The contained exception was: %s", toString().c_str(), e.what());
		throw e;
	}
}

/*
Validates the signature of a signed message.

:param signature: The signature to be validated as *bytes*.
:param message: The message to be validated as *bytes*.
:returns: True if the signature is valid, otherwise False.
:raises: *KeyError* if the instance does not hold a public key.
*/
bool Identity::validate(const Bytes& signature, const Bytes& message) const {
	assert(_object);
	if (_object->_pub) {
		// Guard against a short/empty signing key (e.g. a truncated public key
		// from a malformed announce). Ed25519 verify reads a fixed 32-byte
		// point and would deref past the buffer — an uncatchable hardware
		// fault, so the try/catch below cannot save us.
		if (!_object->_sig_pub || _object->_sig_pub_bytes.size() != Type::Identity::KEYSIZE/8/2) {
			return false;
		}
		try {
			TRACEF("Identity::validate: Attempting to verify signature: %s and message: %s", signature.toHex().c_str(), message.toHex().c_str());
			return _object->_sig_pub->verify(signature, message);
		}
		catch (const std::exception& e) {
			return false;
		}
	}
	else {
		throw std::runtime_error("Signature validation failed because identity does not hold a public key");
	}
}

void Identity::prove(const Packet& packet, const Destination& destination /*= {Type::NONE}*/) const {
	assert(_object);
	Bytes signature(sign(packet.packet_hash()));
	Bytes proof_data;
	if (RNS::Reticulum::should_use_implicit_proof()) {
		proof_data = signature;
		TRACEF("Identity::prove: implicit proof data: %s", proof_data.toHex().c_str());
	}
	else {
		proof_data = packet.packet_hash() + signature;
		TRACEF("Identity::prove: explicit proof data: %s", proof_data.toHex().c_str());
	}
	
	if (!destination) {
		TRACE("Identity::prove: proving packet with proof destination...");
		ProofDestination proof_destination = packet.generate_proof_destination();
		Packet proof(proof_destination, packet.receiving_interface(), proof_data, Type::Packet::PROOF);
		proof.send();
	}
	else {
		TRACE("Identity::prove: proving packet with specified destination...");
		Packet proof(destination, packet.receiving_interface(), proof_data, Type::Packet::PROOF);
		proof.send();
	}
}

void Identity::prove(const Packet& packet) const {
	prove(packet, {Type::NONE});
}
