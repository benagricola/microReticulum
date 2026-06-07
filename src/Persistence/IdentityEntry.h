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

#include "Bytes.h"
#include "Utilities/Memory.h"

// CBA microStore
#include <microStore/TieredStore.h>   // pulls in HeapStore.h + FileStore.h
#include <microStore/TypedStore.h>
#include <microStore/Codec.h>

namespace RNS { namespace Persistence {

// One cached destination identity: the public key (so we can encrypt to the
// destination) plus the app_data last heard in its announce, and the two
// timestamps the eviction policy reads.
class IdentityEntry {
public:
	IdentityEntry() {}
	IdentityEntry(double timestamp, const RNS::Bytes& packet_hash, const RNS::Bytes& public_key,
	              const RNS::Bytes& app_data, double last_used = 0) :
		_timestamp(timestamp),
		_packet_hash(packet_hash),
		_public_key(public_key),
		_app_data(app_data),
		_last_used(last_used)
	{
	}
	// A decoded entry is valid once it carries a public key (the only field a
	// recall actually needs). Lets callers test the result of a get().
	inline operator bool() const { return _public_key.size() > 0; }
public:
	// _timestamp is the last-announce/learned time (overwritten on every announce
	// by remember()). _last_used is the refresh-on-use (LRU) marker mirroring
	// upstream known_destinations[dest][4]:
	//   >0  last-use timestamp (set by recall() on a real use)
	//    0  learned-but-never-used
	//   <0  retained/pinned, never evicted
	double _timestamp = 0;
	RNS::Bytes _packet_hash;
	RNS::Bytes _public_key;
	RNS::Bytes _app_data;
	double _last_used = 0;
};

// The known-destinations identity cache is a two-tier store: a PSRAM/heap front
// (always) plus an optional flash persist tier gated at init() by
// RNS_PERSIST_KNOWN_DESTS. The front absorbs the announce-rate churn and the
// front-only LRU touches (put_front); the persist tier sees only genuine
// identity changes (remember/retain) and is written per-record — replacing the
// old full-blob rewrite that froze the loop ~22 s on a full table.
using KnownDestStore = microStore::BasicTieredStore<Utilities::Memory::ContainerAllocator<uint8_t>>;
using KnownDestTable = microStore::TypedStore<Bytes, IdentityEntry, KnownDestStore>;

} }

namespace microStore {
template<>
struct Codec<RNS::Persistence::IdentityEntry>
{
	static std::vector<uint8_t> encode(const RNS::Persistence::IdentityEntry& entry);
	static bool decode(const std::vector<uint8_t>& data, RNS::Persistence::IdentityEntry& entry);
};
}
