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

#include "Identity.h"
#include "Log.h"
#include "Bytes.h"
#include "Type.h"
#include "Utilities/Memory.h"

#include <ArduinoJson.h>

#include <list>
#include <memory>
#include <array>
#include <cassert>
#include <stdint.h>

namespace RNS {

	class Interface;
	class Packet;
	using HInterface = std::shared_ptr<Interface>;

	class AnnounceEntry {
	public:
		AnnounceEntry() {}
		AnnounceEntry(const Bytes& destination, double time, uint8_t hops, double emitted, const Bytes& raw) :
			_destination(destination),
			_time(time),
			_hops(hops),
			_emitted(emitted),
			_raw(raw) {}
	public:
		Bytes _destination;
		double _time = 0;
		uint8_t _hops = 0;
		uint64_t _emitted = 0;
		Bytes _raw;
	};

	// Ingress Control (ported from RNS Interfaces/Interface.py). When inbound
	// announces arrive faster than a per-interface threshold, announces for
	// unknown destinations are HELD in a bounded set and released slowly
	// (lowest-hop first) instead of being processed/propagated immediately.
	// This throttles an announce flood at ingress.

	// A held inbound announce. Upstream stores the whole RNS.Packet keyed by
	// destination hash; here we keep only what process_held_announces()/release
	// needs: the raw frame to re-inject via Transport::inbound(), the hop count
	// (for lowest-hop selection) and the destination hash (the map key + the
	// pop key on release).
	class HeldAnnounce {
	public:
		HeldAnnounce() {}
		HeldAnnounce(const Bytes& destination_hash, uint8_t hops, const Bytes& raw) :
			_destination_hash(destination_hash),
			_hops(hops),
			_raw(raw) {}
	public:
		Bytes _destination_hash;
		uint8_t _hops = 0;
		Bytes _raw;
	};

	// Fixed-capacity timestamp ring mirroring upstream's
	// collections.deque(maxlen=IA_FREQ_SAMPLES). Append drops the oldest once
	// full; front() peeks the oldest; pop_front() removes it. Backed by a plain
	// std::array (IA_FREQ_SAMPLES doubles, ~384 B) — small + fixed, so it stays
	// in SRAM rather than going through the PSRAM container allocator.
	template <size_t N>
	class TimestampRing {
	public:
		inline void append(double t) {
			if (_count < N) {
				_buf[(_head + _count) % N] = t;
				++_count;
			}
			else {
				// Full: overwrite oldest, advance head (deque maxlen semantics).
				_buf[_head] = t;
				_head = (_head + 1) % N;
			}
		}
		inline void pop_front() {
			if (_count > 0) {
				_head = (_head + 1) % N;
				--_count;
			}
		}
		inline double front() const { return _buf[_head]; }
		inline size_t size() const { return _count; }
	private:
		std::array<double, N> _buf {};
		size_t _head = 0;
		size_t _count = 0;
	};

	class InterfaceImpl : public std::enable_shared_from_this<InterfaceImpl> {

	protected:
		InterfaceImpl() { MEMF("InterfaceImpl object created, this: 0x%X", this); }
		InterfaceImpl(const char* name) : _name(name) { MEMF("InterfaceImpl object created, this: 0x%X", this); }
	public:
		virtual ~InterfaceImpl() { MEMF("InterfaceImpl object destroyed, this: 0x%X", this); }

	protected:
		virtual bool start() { return true; }
		virtual void stop() {}
		virtual void loop() {}

		// CBA Virtual override method for custom interface to send outgoing data
		virtual void send_outgoing(const Bytes& data) = 0;
		
		// CBA Internal method to handle housekeeping for data going out on interface
		void handle_outgoing(const Bytes& data);
		// CBA Internal method to handle data coming in on interface and pass on to transport
		virtual void handle_incoming(const Bytes& data);

		virtual const Bytes get_hash() const {
			return Identity::full_hash({toString()});
		}

		virtual inline std::string toString() const { return "Interface[" + _name + "]"; }

	protected:
		Interface* _parent = nullptr;
		bool _IN  = false;
		bool _OUT = false;
		bool _FWD = false;
		bool _RPT = false;
		std::string _name;
		size_t _rxb = 0;
		size_t _txb = 0;
		bool _online = false;
		// Interface access codes (IFAC). When _ifac_identity is set, this is a
		// private interface: outbound packets are masked + signed and inbound
		// packets must carry a valid access code. _ifac_key is the HKDF salt for
		// the per-packet mask; _ifac_size is the access-code length in bytes.
		Identity _ifac_identity = {Type::NONE};
		Bytes _ifac_key;
		uint16_t _ifac_size = 0;
		Type::Interface::modes _mode = Type::Interface::MODE_NONE;
		uint32_t _bitrate = 0;
		uint16_t _HW_MTU = 0;
		bool _AUTOCONFIGURE_MTU = false;
		bool _FIXED_MTU = false;
		double _announce_allowed_at = 0;
		// Fraction of interface airtime allotted to announce egress. Upstream
		// reads this per-interface from config (default Reticulum.ANNOUNCE_CAP%);
		// we default every interface to that 2% so the queue-drain wait-time
		// math stays active. A 0.0 cap skips the math and (with the queue now
		// draining) would let a second same-tick announce strand permanently.
		float _announce_cap = (float)Type::Reticulum::ANNOUNCE_CAP / 100.0f;
		std::list<AnnounceEntry> _announce_queue;
		// Announce flood protection (opt-in; 0 target = disabled, the default).
		// Minimum seconds between announces from a single destination on this
		// interface; repeated violations beyond the grace count block rebroadcast
		// until target+penalty seconds have passed.
		double _announce_rate_target = 0;
		uint32_t _announce_rate_grace = 0;
		double _announce_rate_penalty = 0;
		// Ingress Control state (ported from RNS Interfaces/Interface.py
		// ic_* fields ~line 100-135). On by default; should_ingress_limit()
		// is a no-op when _ingress_control is false.
		bool _ingress_control = true;
		bool _ic_burst_active = false;
		double _ic_burst_activated = 0;
		// Next time (OS::time seconds) a held announce may be released.
		double _ic_held_release = 0;
		// Interface creation time (OS::time seconds); age() = now - created.
		double _ic_created = 0;
		// Bounded set of held announces keyed by destination hash. PSRAM-backed
		// (ContainerMap) like the path tables, since it is growth-prone up to
		// MAX_HELD_ANNOUNCES entries. Capped on insert in hold_announce().
		Utilities::Memory::ContainerMap<Bytes, HeldAnnounce> _held_announces;
		// Inbound-announce timestamp ring for the frequency calculation.
		TimestampRing<Type::Interface::IA_FREQ_SAMPLES> _ia_freq_ring;
		bool _is_connected_to_shared_instance = false;
		bool _is_local_shared_instance = false;
		//Bytes _hash;
		HInterface _parent_interface;
		//Transport& _owner;

	friend class Interface;
	};

	class Interface {

	public:
		// Which interface modes a Transport Node
		// should actively discover paths for.
		static uint8_t DISCOVER_PATHS_FOR;

		// Total announces drained from interface egress queues since boot (one
		// per process_announce_queue() send). A climbing value confirms queued
		// re-broadcasts are reaching the wire; flat-at-zero means they are not.
		static uint32_t drained_announces() { return _drained_announces; }

	public:
		Interface(Type::NoneConstructor none) {
			MEMF("Interface NONE object created, this: 0x%X, impl: 0x%X", this, _impl.get());
		}
		Interface(const Interface& obj) : _impl(obj._impl) {
			MEMF("Interface object copy created, this: 0x%X, impl: 0x%X", this, _impl.get());
		}
		Interface(std::shared_ptr<InterfaceImpl>& impl) : _impl(impl) {
			MEMF("Interface object created with shared impl, this: 0x%X, impl: 0x%X", this, _impl.get());
		}
		Interface(InterfaceImpl* impl) : _impl(impl) {
			MEMF("Interface object created with new impl, this: 0x%X, impl: 0x%X", this, _impl.get());
		}
		virtual ~Interface() {
			MEMF("Interface object destroyed, this: 0x%X, impl: 0x%X", this, _impl.get());
		}

		inline Interface& operator = (const Interface& obj) {
			_impl = obj._impl;
			MEMF("Interface object copy created by assignment, this: 0x%X, impl: 0x%X", this, _impl.get());
			return *this;
		}
		inline Interface& operator = (InterfaceImpl* impl) {
			_impl.reset(impl);
			MEMF("Interface object copy created by assignment, this: 0x%X, impl: 0x%X", this, _impl.get());
			return *this;
		}
		inline operator bool() const {
			MEMF("Interface object bool, this: 0x%X, impl: 0x%X", this, _impl.get());
			return _impl.get() != nullptr;
		}
		inline bool operator < (const Interface& obj) const {
			MEMF("Interface object <, this: 0x%X, impl: 0x%X", this, _impl.get());
			return _impl.get() < obj._impl.get();
		}
		inline bool operator > (const Interface& obj) const {
			MEMF("Interface object <, this: 0x%X, impl: 0x%X", this, _impl.get());
			return _impl.get() > obj._impl.get();
		}
		inline bool operator == (const Interface& obj) const {
			MEMF("Interface object ==, this: 0x%X, impl: 0x%X", this, _impl.get());
			return _impl.get() == obj._impl.get();
		}
		inline bool operator != (const Interface& obj) const {
			MEMF("Interface object !=, this: 0x%X, impl: 0x%X", this, _impl.get());
			return _impl.get() != obj._impl.get();
		}
		inline InterfaceImpl* get() {
			return _impl.get();
		}
		inline void clear() {
			_impl.reset();
		}

	public:
		inline bool start() { assert(_impl); return _impl->start(); }
		inline void stop() { assert(_impl); _impl->stop(); }
		inline void loop() { assert(_impl); _impl->loop(); }
		inline const Bytes get_hash() const { assert(_impl); return _impl->get_hash(); }
		void process_announce_queue();

		// Ingress Control (ported from RNS Interfaces/Interface.py).
		// Seconds since this interface impl was created (now - _ic_created).
		double age() const;
		// Record an inbound announce timestamp into the frequency ring.
		void received_announce();
		// Inbound announce frequency (Hz) over the ring, matching upstream's
		// incoming_announce_frequency() including the decay popleft side-effect.
		double incoming_announce_frequency();
		// Burst-detection state machine. Returns true while the interface is
		// ingress-limiting (announces should be held, not processed). No-op
		// (returns false) when ingress_control is disabled.
		bool should_ingress_limit();
		// Hold an announce for slow release. Bounded to MAX_HELD_ANNOUNCES.
		void hold_announce(const Packet& announce_packet);
		// Slowly release held announces (lowest-hop first), re-injecting via
		// Transport::inbound on this interface. Cooperative poll replacement
		// for upstream's per-release threading.Thread.
		void process_held_announces();

		// Derive and install IFAC parameters from a network name/passphrase,
		// turning this into a private interface (matches RNS setup in
		// Reticulum.py). Either netname or netkey may be null but not both.
		void configure_ifac(const char* netname, const char* netkey, uint16_t ifac_size);

		// CBA ACCUMULATES
		inline void add_announce(AnnounceEntry& entry) { assert(_impl); _impl->_announce_queue.push_back(entry); }

	protected:
		// Internal method to handle data going out on interface and pass on to impl
		void send_outgoing(const Bytes& data);
	public:
		// Public method to handle data coming in on interface and pass on to impl
		void handle_incoming(const Bytes& data);

	protected:
		// setters
		inline void IN(bool IN) { assert(_impl); _impl->_IN = IN; }
		inline void OUT(bool OUT) { assert(_impl); _impl->_OUT = OUT; }
		inline void FWD(bool FWD) { assert(_impl); _impl->_FWD = FWD; }
		inline void RPT(bool RPT) { assert(_impl); _impl->_RPT = RPT; }
		inline void name(const char* name) { assert(_impl); _impl->_name = name; }
		inline void online(bool online) { assert(_impl); _impl->_online = online; }
		inline void announce_allowed_at(double announce_allowed_at) { assert(_impl); _impl->_announce_allowed_at = announce_allowed_at; }
	public:
		// getters
		inline bool IN() const { assert(_impl); return _impl->_IN; }
		inline bool OUT() const { assert(_impl); return _impl->_OUT; }
		inline bool FWD() const { assert(_impl); return _impl->_FWD; }
		inline bool RPT() const { assert(_impl); return _impl->_RPT; }
		inline bool online() const { assert(_impl); return _impl->_online; }
		inline std::string name() const { assert(_impl); return _impl->_name; }
		inline const Identity& ifac_identity() const { assert(_impl); return _impl->_ifac_identity; }
		inline const Bytes& ifac_key() const { assert(_impl); return _impl->_ifac_key; }
		inline uint16_t ifac_size() const { assert(_impl); return _impl->_ifac_size; }
		inline Type::Interface::modes mode() const { assert(_impl); return _impl->_mode; }
		inline void mode(Type::Interface::modes mode) { assert(_impl); _impl->_mode = mode; }
		inline uint32_t bitrate() const { assert(_impl); return _impl->_bitrate; }
		// Public so the firmware can seed the interface from the radio's
		// computed on-air bitrate (announce-egress shaping, airtime estimates).
		inline void bitrate(uint32_t bitrate) { assert(_impl); _impl->_bitrate = bitrate; }
		inline uint16_t HW_MTU() const { assert(_impl); return _impl->_HW_MTU; }
		inline bool AUTOCONFIGURE_MTU() const { assert(_impl); return _impl->_AUTOCONFIGURE_MTU; }
		inline bool FIXED_MTU() const { assert(_impl); return _impl->_FIXED_MTU; }
		inline double announce_allowed_at() const { assert(_impl); return _impl->_announce_allowed_at; }
		inline float announce_cap() const { assert(_impl); return _impl->_announce_cap; }
		inline double announce_rate_target() const { assert(_impl); return _impl->_announce_rate_target; }
		inline void announce_rate_target(double target) { assert(_impl); _impl->_announce_rate_target = target; }
		inline uint32_t announce_rate_grace() const { assert(_impl); return _impl->_announce_rate_grace; }
		inline void announce_rate_grace(uint32_t grace) { assert(_impl); _impl->_announce_rate_grace = grace; }
		inline double announce_rate_penalty() const { assert(_impl); return _impl->_announce_rate_penalty; }
		inline void announce_rate_penalty(double penalty) { assert(_impl); _impl->_announce_rate_penalty = penalty; }
		inline bool ingress_control() const { assert(_impl); return _impl->_ingress_control; }
		inline void ingress_control(bool ingress_control) { assert(_impl); _impl->_ingress_control = ingress_control; }
		inline size_t held_announces_count() const { assert(_impl); return _impl->_held_announces.size(); }
		inline size_t rxb() const { assert(_impl); return _impl->_rxb; }
		inline size_t txb() const { assert(_impl); return _impl->_txb; }
		inline std::list<AnnounceEntry>& announce_queue() const { assert(_impl); return _impl->_announce_queue; }
		inline bool is_connected_to_shared_instance() const { assert(_impl); return _impl->_is_connected_to_shared_instance; }
		inline bool is_local_shared_instance() const { assert(_impl); return _impl->_is_local_shared_instance; }
		inline HInterface parent_interface() const { assert(_impl); return _impl->_parent_interface; }

		virtual inline std::string toString() const { if (!_impl) return ""; return _impl->toString(); }

#ifndef NDEBUG
		inline std::string debugString() const {
			std::string dump;
			dump = "Interface object, this: " + std::to_string((uintptr_t)this) + ", data: " + std::to_string((uintptr_t)_impl.get());
			return dump;
		}
#endif

	protected:
		std::shared_ptr<InterfaceImpl> _impl;

		static uint32_t _drained_announces;

	friend class Transport;
	};

}

/*
namespace ArduinoJson {
	inline bool convertToJson(const RNS::Interface& src, JsonVariant dst) {
		TRACE("<<< Serializing Interface");
		if (!src) {
			return dst.set(nullptr);
		}
		TRACEF("<<< Interface hash %s", src.get_hash().toHex().c_str());
		return dst.set(src.get_hash().toHex());
	}
	void convertFromJson(JsonVariantConst src, RNS::Interface& dst);
	inline bool canConvertFromJson(JsonVariantConst src, const RNS::Interface&) {
		return src.is<const char*>() && strlen(src.as<const char*>()) == 64;
	}
}
*/
/*
namespace ArduinoJson {
	template <>
	struct Converter<RNS::Interface> {
		static bool toJson(const RNS::Interface& src, JsonVariant dst) {
			if (!src) {
				return dst.set(nullptr);
			}
			TRACEF("<<< Serializing interface hash %s", src.get_hash().toHex().c_str());
			return dst.set(src.get_hash().toHex());
		}
		static RNS::Interface fromJson(JsonVariantConst src) {
			if (!src.isNull()) {
				RNS::Bytes hash;
				hash.assignHex(src.as<const char*>());
				TRACEF(">>> Deserialized interface hash %s", hash.toHex().c_str());
				TRACE(">>> Querying transport for interface");
				// Query transport for matching interface
				return RNS::Interface::find_interface_from_hash(hash);
			}
			else {
				return {RNS::Type::NONE};
			}
		}
		static bool checkJson(JsonVariantConst src) {
			return src.is<const char*>() && strlen(src.as<const char*>()) == 64;
		}
	};
}
*/