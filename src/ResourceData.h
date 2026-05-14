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

#include "Resource.h"
#include "ResourceBuffer.h"

#include "Link.h"
#include "Bytes.h"
#include "Type.h"
#include "Cryptography/Fernet.h"

#include <memory>
#include <vector>

namespace RNS {

class ResourceData {
public:
	ResourceData(const Link& link) : _link(link) {}
	virtual ~ResourceData() {}

private:
	// --- Identity ---
	Link  _link;                                  // Underlying Link this resource transfers over
	Bytes _hash;                                  // 16 B truncated resource hash
	Bytes _random_hash;                           // 4 B salt
	Bytes _expected_proof;                        // 32 B SHA-256 of (data || hash); sender uses to verify PRF
	Bytes _original_hash;                         // 16 B; for single-segment == _hash
	Bytes _request_id;                            // 16 B; empty for non-request resources

	// --- Payload state ---
	// Sender side: _encrypted holds the post-Link-encrypt bytes after build().
	// Receiver side: payload is streamed into _buffer (heap or flash); _encrypted unused.
	Bytes _encrypted;
	std::unique_ptr<ResourceBuffer> _buffer;
	// Sender side: pre-packed RESOURCE packet bodies + their map_hashes, indexed by part.
	std::vector<Bytes> _parts;
	std::vector<Bytes> _map_hashes;
	// Sender side: full hashmap blob (n * 4 bytes). _map_hashes is the
	// per-part split form, _map_full is the concatenated form used to
	// fill the ADV's `m` field and slice into HMU segments.
	Bytes _map_full;
	// Receiver side: per-part received flag and sliding window state.
	std::vector<bool>  _parts_received;

	uint32_t _transfer_size  = 0;                 // _t in ADV (post-encrypt bytes on wire)
	uint32_t _data_size      = 0;                 // _d in ADV (uncompressed; equals _t in our port)
	uint16_t _parts_count    = 0;                 // _n in ADV
	uint16_t _sdu            = 0;                 // bytes per part (derived from Link MDU)

	// Single-segment port: these are fixed at 1/1/false.
	uint8_t _segment_index   = 1;
	uint8_t _total_segments  = 1;
	bool    _is_split        = false;
	bool    _is_request      = false;
	bool    _is_response     = false;
	bool    _has_metadata    = false;
	bool    _compressed      = false;
	bool    _encrypted_flag  = true;              // _f bit 0 — always set, we always encrypt

	// --- Receiver progress (filled in during TRANSFERRING) ---
	int32_t  _consecutive_completed_height = -1;
	uint16_t _received_count    = 0;
	uint16_t _outstanding_parts = 0;
	uint16_t _window            = Type::Resource::WINDOW;  // fixed at 4 for this port

	// --- Sender progress ---
	uint16_t _sent_parts        = 0;
	uint8_t  _retries_left      = Type::Resource::MAX_RETRIES;
	uint8_t  _adv_retries_left  = Type::Resource::MAX_ADV_RETRIES;

	// --- Timing (millis since boot, via OS::ltime()) ---
	uint64_t _last_activity_ms = 0;
	uint64_t _adv_sent_ms      = 0;
	uint64_t _req_sent_ms      = 0;
	uint64_t _started_ms       = 0;
	double   _rtt              = 0.0;             // seconds; populated from Link.rtt at construction
	double   _timeout          = 0.0;             // seconds; full-resource watchdog

	// --- State ---
	Type::Resource::status _status = Type::Resource::NONE;
	bool _initiator = false;                      // true on sender, false on receiver

	// --- Callbacks ---
	Resource::Callbacks _callbacks;

friend class Resource;
};

}  // namespace RNS
