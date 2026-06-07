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

#include "IdentityEntry.h"

#include <cstring>

using namespace RNS;
using namespace RNS::Persistence;

// Wire format (per record, little-endian doubles as raw bytes — host is the
// only reader/writer so byte order needn't be portable):
//   double   timestamp
//   double   last_used
//   uint16_t packet_hash_len   then packet_hash bytes
//   uint16_t public_key_len    then public_key bytes
//   uint16_t app_data_len      then app_data bytes
/*static*/ std::vector<uint8_t> microStore::Codec<IdentityEntry>::encode(const IdentityEntry& entry) {
	// An entry with no public key can't be recalled — refuse to persist a
	// zero-length value (which the FileStore would reject anyway).
	if (entry._public_key.size() == 0) return {};

	std::vector<uint8_t> out;
	auto write = [&](const void* ptr, size_t len) {
		const uint8_t* p = (const uint8_t*)ptr;
		out.insert(out.end(), p, p + len);
	};
	auto write_bytes = [&](const RNS::Bytes& b) {
		uint16_t len = (uint16_t)b.size();
		write(&len, sizeof(len));
		if (len) out.insert(out.end(), b.collection().begin(), b.collection().end());
	};

	write(&entry._timestamp, sizeof(entry._timestamp));
	write(&entry._last_used, sizeof(entry._last_used));
	write_bytes(entry._packet_hash);
	write_bytes(entry._public_key);
	write_bytes(entry._app_data);

	return out;
}

/*static*/ bool microStore::Codec<IdentityEntry>::decode(const std::vector<uint8_t>& data, IdentityEntry& entry) {
	size_t pos = 0;
	auto read = [&](void* dst, size_t len) -> bool {
		if (pos + len > data.size()) return false;
		memcpy(dst, &data[pos], len);
		pos += len;
		return true;
	};
	auto read_bytes = [&](RNS::Bytes& b) -> bool {
		uint16_t len;
		if (!read(&len, sizeof(len))) return false;
		if (pos + len > data.size()) return false;
		b = RNS::Bytes(&data[pos], len);
		pos += len;
		return true;
	};

	if (!read(&entry._timestamp, sizeof(entry._timestamp))) return false;
	if (!read(&entry._last_used, sizeof(entry._last_used))) return false;
	if (!read_bytes(entry._packet_hash)) return false;
	if (!read_bytes(entry._public_key))  return false;
	if (!read_bytes(entry._app_data))    return false;

	return true;
}
