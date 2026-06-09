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
	// Receiver side: post-assembly decrypted body (the LXMF wire bytes,
	// after the 4-byte random_hash prefix is stripped). data() returns
	// this on the receiver. Empty before assembly completes.
	Bytes _plaintext;
	std::unique_ptr<ResourceBuffer> _buffer;
	// Sender side: pre-packed RESOURCE packet bodies, indexed by part.
	std::vector<Bytes> _parts;
	// Sender+receiver: full hashmap blob (n * 4 bytes). Single source of
	// truth for every part's 4-byte map_hash. Sender builds it by
	// appending each computed hash; receiver pre-sizes it to
	// (parts_count * MAPHASH_LEN) zeros at accept time and fills slots
	// via memcpy as ADV/HMU segments arrive. Slot i lives at offset
	// i*MAPHASH_LEN. The previous parallel `std::vector<Bytes>`
	// representation cost ~36 B of internal-SRAM per slot
	// (vector<uint8_t> control block + shared_ptr control block) — at
	// 125 parts that's ~4.5 KiB of DMA-cap-eligible heap drained per
	// transfer, which starved esp-aes' per-call GDMA descriptor alloc.
	Bytes _map_full;
	// Receiver side: presence bitmap for `_map_full`. Bit i is true once
	// slot i has been filled (from the ADV's first-segment hashmap or a
	// later HMU). Sender doesn't use it (sender fills every slot during
	// _build_outgoing). 1 bit per slot, ~16 B for 125 parts.
	std::vector<bool>  _map_hashes_known;
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
	// Adaptive sliding window, ported from upstream RNS Resource.py. Starts at
	// WINDOW(4) and grows toward _window_max on each fully-satisfied window;
	// shrinks on a part timeout. _window_min ratchets up with the window;
	// _window_max ramps between WINDOW_MAX_VERY_SLOW(4)/SLOW(10)/FAST(75) by the
	// measured per-request data rate (_req_data_rtt_rate, bytes/sec).
	uint16_t _window            = Type::Resource::WINDOW;
	uint16_t _window_min        = Type::Resource::WINDOW_MIN;
	uint16_t _window_max        = Type::Resource::WINDOW_MAX_SLOW;
	uint8_t  _fast_rate_rounds      = 0;
	uint8_t  _very_slow_rate_rounds = 0;
	double   _req_data_rtt_rate     = 0.0;

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

	// --- Sender-side ciphertext spill (steps 7/8) ---
	// Once the encrypted blob exceeds RAM_BUFFER_THRESHOLD,
	// _build_outgoing writes it to a temp file under the configured
	// resource-tmp directory and leaves _encrypted empty. _send_part
	// (via _get_part) seeks into that file by part index instead of
	// indexing _parts, so the full ciphertext doesn't dwell in PSRAM
	// for the entire (potentially minutes-long) Resource transfer.
	// Empty string indicates in-memory mode; cleared back to empty on
	// COMPLETE / FAILED / cancel after the underlying file is unlinked.
	std::string _ciphertext_path;

	// --- Rate tracking for airtime-aware window timeout ---
	// `_eifr_bps` is the Effective Interface Rate in bits/sec — the
	// observed throughput of the underlying link, including any duty-
	// cycle / airtime throttling at the radio. The watchdog scales the
	// window timeout to `expected_tof = outstanding_parts * sdu * 8 /
	// eifr_bps`, so a tightly-capped link (e.g. EU 1% sub-band) gets a
	// proportionally longer timeout instead of failing fast.
	// `_rtt_rxd_bytes` is the cumulative bytes received during this
	// resource's lifetime; `_rtt_rxd_bytes_at_part_req` snapshots that
	// counter at the last REQ send, so each window's observed rate is
	// (delta_bytes * 8) / (now - _req_sent_ms). Ported from upstream
	// Resource.py's req_data_rtt_rate + update_eifr() logic.
	double   _eifr_bps                  = 0.0;
	uint64_t _rtt_rxd_bytes             = 0;
	uint64_t _rtt_rxd_bytes_at_part_req = 0;

	// --- State ---
	Type::Resource::status _status = Type::Resource::NONE;
	bool _initiator = false;                      // true on sender, false on receiver

	// --- Callbacks ---
	Resource::Callbacks _callbacks;

friend class Resource;
};

}  // namespace RNS
