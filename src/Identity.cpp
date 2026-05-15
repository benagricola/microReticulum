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

/*static*/ Identity::IdentityTable Identity::_known_destinations;
/*static*/ bool Identity::_saving_known_destinations = false;
// CBA
// CBA ACCUMULATES
/*static*/ uint16_t Identity::_known_destinations_maxsize = RNS_KNOWN_DESTINATIONS_MAX;

// Binary serialisation helpers used by save_known_destinations /
// load_known_destinations. Defined here at file scope so both functions
// can see them (the file's compilation order otherwise puts save before
// load).
namespace {
constexpr uint32_t KD_MAGIC   = 0xC0DEC0DE;
constexpr uint32_t KD_VERSION = 1;
void put_u16(Bytes& b, uint16_t v) {
	uint8_t tmp[2] = {(uint8_t)(v >> 8), (uint8_t)v};
	b.append(tmp, 2);
}
void put_u32(Bytes& b, uint32_t v) {
	uint8_t tmp[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16),
	                  (uint8_t)(v >> 8),  (uint8_t)v};
	b.append(tmp, 4);
}
void put_u64(Bytes& b, uint64_t v) {
	uint8_t tmp[8];
	for (int i = 0; i < 8; ++i) tmp[i] = (uint8_t)(v >> (56 - 8 * i));
	b.append(tmp, 8);
}
void put_bytes(Bytes& b, const Bytes& src) {
	put_u16(b, (uint16_t)src.size());
	if (src.size()) b.append(src.data(), src.size());
}
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
			_known_destinations.insert({destination_hash, {OS::time(), packet_hash, public_key, app_data}});
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
Recall identity for a destination hash.

:param destination_hash: Destination hash as *bytes*.
:returns: An :ref:`RNS.Identity<api-identity>` instance that can be used to create an outgoing :ref:`RNS.Destination<api-destination>`, or *None* if the destination is unknown.
*/
/*static*/ Identity Identity::recall(const Bytes& destination_hash) {
	TRACE("Identity::recall...");
	auto iter = _known_destinations.find(destination_hash);
	if (iter != _known_destinations.end()) {
		TRACEF("Identity::recall: Found identity entry for destination %s", destination_hash.toHex().c_str());
		const IdentityEntry& identity_data = (*iter).second;
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
			Identity identity(false);
			identity.load_public_key(registered_destination.identity().get_public_key());
			identity.app_data({Bytes::NONE});
			return identity;
		}
		TRACEF("Identity::recall: Unable to find destination %s", destination_hash.toHex().c_str());
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
	auto iter = _known_destinations.find(destination_hash);
	if (iter != _known_destinations.end()) {
		TRACEF("Identity::recall_app_data: Found identity entry for destination %s", destination_hash.toHex().c_str());
		const IdentityEntry& identity_data = (*iter).second;
		return identity_data._app_data;
	}
	else {
		TRACEF("Identity::recall_app_data: Unable to find identity entry for destination %s", destination_hash.toHex().c_str());
		return {Bytes::NONE};
	}
}

/*static*/ bool Identity::save_known_destinations() {
	bool success = false;
	try {
		if (_saving_known_destinations) {
			double wait_interval = 0.2;
			double wait_timeout = 5;
			double wait_start = OS::time();
			while (_saving_known_destinations) {
				OS::sleep(wait_interval);
				if (OS::time() > (wait_start + wait_timeout)) {
					ERROR("Could not save known destinations to storage, waiting for previous save operation timed out.");
					return false;
				}
			}
		}

		_saving_known_destinations = true;
		const double save_start = OS::time();

		// Serialize the entire table into a binary blob (see format
		// comment near load_known_destinations).
		Bytes buf;
		put_u32(buf, KD_MAGIC);
		put_u32(buf, KD_VERSION);
		put_u16(buf, (uint16_t)_known_destinations.size());
		for (const auto& [destination_hash, entry] : _known_destinations) {
			put_bytes(buf, destination_hash);
			put_u64(buf, (uint64_t)(entry._timestamp * 1000.0));
			put_bytes(buf, entry._packet_hash);
			put_bytes(buf, entry._public_key);
			put_bytes(buf, entry._app_data);
		}

		char path[Type::Reticulum::FILEPATH_MAXSIZE];
		snprintf(path, Type::Reticulum::FILEPATH_MAXSIZE, "%s/known_destinations",
		         Reticulum::storagepath());
		const size_t wrote = OS::write_file(path, buf);
		if (wrote == buf.size()) {
			DEBUGF("Identity: saved %u known destinations (%u bytes) in %.3fs",
			       (unsigned)_known_destinations.size(),
			       (unsigned)buf.size(),
			       OS::round(OS::time() - save_start, 3));
			success = true;
		}
		else {
			ERRORF("Identity: known_destinations write truncated (%u of %u bytes)",
			       (unsigned)wrote, (unsigned)buf.size());
		}
	}
	catch (const std::exception& e) {
		ERRORF("Error while saving known destinations to disk, the contained exception was: %s", e.what());
	}

	_saving_known_destinations = false;

	return success;
}

// Binary wire format for the known_destinations persistence file. Single
// file, replaced atomically (well, write-then-rename would be — for now,
// write-truncate which is fine because the file is only loaded at boot
// and the old data is acceptable on read failure):
//
//   uint32_t  magic       = 0xC0DEC0DE
//   uint32_t  version     = 1
//   uint16_t  count
//   for each of `count` entries:
//     uint16_t dest_hash_len      then dest_hash bytes
//     uint64_t timestamp_ms       (entry._timestamp converted to ms-since-epoch
//                                  for storage stability across rebuilds)
//     uint16_t pkt_hash_len       then pkt_hash bytes
//     uint16_t pub_key_len        then pub_key bytes
//     uint16_t app_data_len       then app_data bytes
//
// Average entry: 16 (dest_hash) + 8 (ts) + 16 (pkt_hash) + 32 (pub_key) +
// ~100 (app_data) + 8 (length prefixes) ≈ 180 bytes. 100 entries × 180 B
// ≈ 18 KiB, well within LittleFS budget.

/*static*/ void Identity::load_known_destinations() {
	try {
		char path[Type::Reticulum::FILEPATH_MAXSIZE];
		snprintf(path, Type::Reticulum::FILEPATH_MAXSIZE, "%s/known_destinations",
		         Reticulum::storagepath());
		if (!OS::file_exists(path)) {
			DEBUG("Identity: no known_destinations file, starting with empty cache");
			return;
		}
		Bytes buf;
		if (OS::read_file(path, buf) == 0) {
			WARNING("Identity: known_destinations file present but unreadable");
			return;
		}
		const uint8_t* p   = buf.data();
		const uint8_t* end = p + buf.size();
		auto need = [&](size_t n) { return (size_t)(end - p) >= n; };
		auto read_u16 = [&]() -> uint16_t {
			uint16_t v = ((uint16_t)p[0] << 8) | p[1]; p += 2; return v;
		};
		auto read_u32 = [&]() -> uint32_t {
			uint32_t v = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
			             ((uint32_t)p[2] << 8)  | p[3]; p += 4; return v;
		};
		auto read_u64 = [&]() -> uint64_t {
			uint64_t v = 0;
			for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
			p += 8; return v;
		};
		auto read_bytes = [&]() -> Bytes {
			if (!need(2)) return Bytes();
			uint16_t len = read_u16();
			if (!need(len)) return Bytes();
			Bytes b(p, len); p += len; return b;
		};

		if (!need(10)) { WARNING("Identity: known_destinations file truncated"); return; }
		uint32_t magic = read_u32();
		if (magic != KD_MAGIC) {
			WARNINGF("Identity: known_destinations bad magic 0x%08x — discarding", (unsigned)magic);
			return;
		}
		uint32_t version = read_u32();
		if (version != KD_VERSION) {
			WARNINGF("Identity: known_destinations file version %u not supported (expected %u) — discarding", (unsigned)version, (unsigned)KD_VERSION);
			return;
		}
		uint16_t count = read_u16();
		_known_destinations.clear();
		uint16_t loaded = 0;
		for (uint16_t i = 0; i < count; ++i) {
			Bytes dest_hash = read_bytes();
			if (!need(8)) break;
			uint64_t ts_ms  = read_u64();
			Bytes pkt_hash  = read_bytes();
			Bytes pub_key   = read_bytes();
			Bytes app_data  = read_bytes();
			if (dest_hash.size() != Type::Reticulum::TRUNCATED_HASHLENGTH / 8) continue;
			if (pub_key.size()   != Type::Identity::KEYSIZE / 8) continue;
			double ts = (double)ts_ms / 1000.0;
			try {
				_known_destinations.insert({dest_hash, {ts, pkt_hash, pub_key, app_data}});
				loaded++;
			}
			catch (const std::bad_alloc&) {
				ERROR("Identity: bad_alloc while loading known_destinations — stopping early");
				break;
			}
		}
		NOTICEF("Identity: loaded %u known destinations from disk", (unsigned)loaded);
	}
	catch (const std::exception& e) {
		ERRORF("Identity::load_known_destinations exception: %s", e.what());
	}
}

/*static*/ void Identity::cull_known_destinations() {
	TRACE("Identity::cull_known_destinations()");
	if (_known_destinations.size() > _known_destinations_maxsize) {
		try {
			// Build lightweight (timestamp, key) index to avoid copying full IdentityEntry
			// objects — prevents OOM on heap-constrained devices when the table is full.
			std::vector<std::pair<double, Bytes>> sorted_keys;
			sorted_keys.reserve(_known_destinations.size());
			for (const auto& [key, entry] : _known_destinations) {
				sorted_keys.emplace_back(entry._timestamp, key);
			}
			// Sort ascending by timestamp (oldest first)
			std::sort(sorted_keys.begin(), sorted_keys.end());

			uint16_t count = 0;
			for (const auto& [timestamp, destination_hash] : sorted_keys) {
				TRACEF("Identity::cull_known_destinations: Removing destination %s from known destinations", destination_hash.toHex().c_str());
				if (_known_destinations.erase(destination_hash) < 1) {
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
			// Fallback: std::min_element does no heap allocation — erase one oldest entry
			auto oldest = std::min_element(
				_known_destinations.begin(), _known_destinations.end(),
				[](const std::pair<const Bytes, IdentityEntry>& a,
			   const std::pair<const Bytes, IdentityEntry>& b) {
				return a.second._timestamp < b.second._timestamp;
			}
			);
			if (oldest != _known_destinations.end()) {
				_known_destinations.erase(oldest);
			}
		}
		catch (const std::exception& e) {
			ERRORF("cull_known_destinations: exception: %s", e.what());
		}
	}
}

/*static*/ bool Identity::validate_announce(const Packet& packet) {
	try {
		if (packet.packet_type() == Type::Packet::ANNOUNCE) {
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
					auto iter = _known_destinations.find(packet.destination_hash());
					if (iter != _known_destinations.end()) {
						IdentityEntry& identity_entry = (*iter).second;
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

/*static*/ void Identity::persist_data() {
	if (!Transport::reticulum() || !Transport::reticulum().is_connected_to_shared_instance()) {
		save_known_destinations();
	}
}

/*static*/ void Identity::exit_handler() {
	persist_data();
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
	TRACEF("Identity::encrypt: plaintext:  %s", plaintext.toHex().c_str());
	Bytes ciphertext = token.encrypt(plaintext);
	TRACEF("Identity::encrypt: ciphertext: %s", ciphertext.toHex().c_str());

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
