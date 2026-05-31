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

#include "Interface.h"

#include "Identity.h"
#include "Transport.h"
#include "Utilities/OS.h"
#include "Cryptography/HKDF.h"

using namespace RNS;
using namespace RNS::Type::Interface;
using namespace RNS::Utilities;

/*static*/ uint8_t Interface::DISCOVER_PATHS_FOR = MODE_ACCESS_POINT | MODE_GATEWAY;

/*static*/ uint32_t Interface::_drained_announces = 0;

void InterfaceImpl::handle_outgoing(const Bytes& data) {
	//TRACEF("InterfaceImpl.handle_outgoing: data: %s", data.toHex().c_str());
	//TRACE("InterfaceImpl.handle_outgoing");
	_txb += data.size();
}

void InterfaceImpl::handle_incoming(const Bytes& data) {
	//TRACEF("InterfaceImpl.handle_incoming: data: %s", data.toHex().c_str());
	//TRACE("InterfaceImpl.handle_incoming");
	_rxb += data.size();
	// Create temporary Interface encapsulating our own shared impl
	std::shared_ptr<InterfaceImpl> self = shared_from_this();
	Interface interface(self);
	// Pass data on to transport for handling
	Transport::inbound(data, interface);
}

void Interface::send_outgoing(const Bytes& data) {
	assert(_impl);
	//TRACEF("Interface.send_outgoing: data: %s", data.toHex().c_str());
	//TRACE("Interface.send_outgoing");
	// Catch exceptions from calls into Interface implementation
	try {
		_impl->send_outgoing(data);
    }
    catch (const std::bad_alloc&) {
		ERROR("Interface::send_outgoing: bad_alloc - OUT OF MEMORY");
		// Critical OOM, restarting
#if defined(ESP32)
		ESP.restart();
#elif defined(ARDUINO_ARCH_NRF52) || defined(ARDUINO_NRF52_ADAFRUIT)
		NVIC_SystemReset();
#endif
    }
    catch (const std::exception& e) {
		ERRORF("Interface::send_outgoing: %s", e.what());
    }
}

void Interface::handle_incoming(const Bytes& data) {
	assert(_impl);
	//TRACEF("Interface.handle_incoming: data: %s", data.toHex().c_str());
	//TRACE("Interface.handle_incoming");
/*
	_impl->_rxb += data.size();
	// Pass data on to transport for handling
	Transport::inbound(data, *this);
*/
	// Catch exceptions from calls into Interface implementation
	try {
		_impl->handle_incoming(data);
    }
    catch (const std::bad_alloc&) {
		ERROR("Interface::handle_incoming: bad_alloc - OUT OF MEMORY");
		// Critical OOM, restarting
#if defined(ESP32)
		ESP.restart();
#elif defined(ARDUINO_ARCH_NRF52) || defined(ARDUINO_NRF52_ADAFRUIT)
		NVIC_SystemReset();
#endif
    }
    catch (const std::exception& e) {
		ERRORF("Interface::handle_incoming: %s", e.what());
    }
}

void Interface::process_announce_queue() {
	assert(_impl);

	// Cooperative announce-egress drain. Ported from RNS
	// Interfaces/Interface.py:323-364. Embedded divergence: upstream arms a
	// threading.Timer per send; on the ESP32 we instead poll this from
	// Reticulum::loop() once per main-loop iteration and self-gate on
	// _announce_allowed_at, draining at most one announce per rate window.
	// Unlike upstream's process_outgoing(raw) — which would send a queued
	// announce unmasked even on an IFAC interface — we route through
	// Transport::transmit() so a queued announce is masked consistently with
	// an immediate send.
	std::list<AnnounceEntry>& queue = _impl->_announce_queue;
	if (queue.empty()) {
		return;
	}

	try {
		double now = OS::time();

		// Expire entries older than QUEUED_ANNOUNCE_LIFE.
		for (auto it = queue.begin(); it != queue.end(); ) {
			if (now > it->_time + (double)Type::Reticulum::QUEUED_ANNOUNCE_LIFE) {
				it = queue.erase(it);
			}
			else {
				++it;
			}
		}
		if (queue.empty()) {
			return;
		}

		// One send per rate window.
		if (now < _impl->_announce_allowed_at) {
			return;
		}

		// Prefer the lowest-hop announce, tie-broken by the oldest queued time.
		auto selected = queue.begin();
		for (auto it = queue.begin(); it != queue.end(); ++it) {
			if (it->_hops < selected->_hops ||
				(it->_hops == selected->_hops && it->_time < selected->_time)) {
				selected = it;
			}
		}

		// Next send is allowed after the selected announce's time-on-air
		// divided by the announce capacity (fraction of airtime for announces).
		double wait_time = 0;
		if (_impl->_bitrate > 0 && _impl->_announce_cap > 0) {
			double tx_time = (double)(selected->_raw.size() * 8) / (double)_impl->_bitrate;
			wait_time = tx_time / _impl->_announce_cap;
		}
		_impl->_announce_allowed_at = now + wait_time;

		TRACEF("Interface.process_announce_queue: draining queued announce (%u remaining) on %s",
			(unsigned)(queue.size() - 1), toString().c_str());
		Transport::transmit(*this, selected->_raw);
		queue.erase(selected);
		_drained_announces++;
	}
	catch (const std::exception& e) {
		// Match upstream: a failure clears the whole queue rather than
		// retrying a poison entry forever.
		ERRORF("Interface::process_announce_queue: %s - clearing announce queue", e.what());
		queue.clear();
	}
}

void Interface::configure_ifac(const char* netname, const char* netkey, uint16_t ifac_size) {
	assert(_impl);
	// Ported from RNS Reticulum.py:898-916. ifac_origin is the concatenation of
	// the network name and passphrase hashes; the IFAC key is HKDF-derived from
	// its hash with the fixed IFAC salt; the IFAC identity (used to sign/verify
	// per-packet access codes) is that key loaded as a private identity.
	Bytes ifac_origin;
	if (netname != nullptr && netname[0] != '\0') {
		ifac_origin << Identity::full_hash(Bytes(netname));
	}
	if (netkey != nullptr && netkey[0] != '\0') {
		ifac_origin << Identity::full_hash(Bytes(netkey));
	}
	Bytes ifac_origin_hash = Identity::full_hash(ifac_origin);

	Bytes ifac_salt;
	ifac_salt.assignHex(Type::Reticulum::IFAC_SALT);
	_impl->_ifac_key = Cryptography::hkdf(64, ifac_origin_hash, ifac_salt);

	Identity ifac_identity(false);
	ifac_identity.load_private_key(_impl->_ifac_key);
	_impl->_ifac_identity = ifac_identity;
	_impl->_ifac_size = ifac_size;

	TRACEF("Interface.configure_ifac: IFAC enabled (size %u) on %s", (unsigned)ifac_size, toString().c_str());
}

/*
void ArduinoJson::convertFromJson(JsonVariantConst src, RNS::Interface& dst) {
	TRACE(">>> Deserializing Interface");
TRACEF(">>> Interface pre: %s", dst.debugString().c_str());
	if (!src.isNull()) {
		RNS::Bytes hash;
		hash.assignHex(src.as<const char*>());
		TRACEF(">>> Querying Transport for Interface hash %s", hash.toHex().c_str());
		// Query transport for matching interface
		dst = Transport::find_interface_from_hash(hash);
TRACEF(">>> Interface post: %s", dst.debugString().c_str());
	}
	else {
		dst = {RNS::Type::NONE};
TRACEF(">>> Interface post: %s", dst.debugString().c_str());
	}
}
*/
