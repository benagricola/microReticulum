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

#include "Bytes.h"

#include "Utilities/Memory.h"

using namespace RNS;

#if defined(BOARD_HAS_PSRAM) && BOARD_HAS_PSRAM == 1
namespace {
	// PSRAM-aware allocator for Bytes::Data + its shared_ptr control block.
	// Without this, every Bytes that owns its data leaves a ~36-byte residue
	// on internal SRAM: the std::vector<uint8_t> control block (12 B) plus
	// the std::shared_ptr control block (~24 B). The byte storage already
	// lives in PSRAM via ContainerAllocator, so this is purely overhead —
	// but at 125 part-hash Bytes per Resource it works out to ~4.5 KiB of
	// DMA-cap-eligible internal heap consumed per transfer, which starves
	// esp-aes' per-call GDMA descriptor alloc and produces the "AES encrypt
	// out of resources" failure the Resource transfer kept hitting.
	//
	// std::allocate_shared<Data>(allocator) places BOTH the Data object and
	// the shared_ptr control block in one combined allocation drawn from
	// the supplied allocator — so we get the control block in PSRAM too.
	Utilities::Memory::ContainerAllocator<uint8_t> s_data_alloc_seed;
}
#endif

// Creates new shared data for instance
// - If capacity is specified (>0) then create empty shared data with initial reserved capacity
// - If capacity is not specified (<=0) then create empty shared data with no initial capacity
void Bytes::newData(size_t capacity /*= 0*/) {
//MEMF("Bytes is creating own data with capacity %u", capacity);
//MEM("newData: Creating new data...");
#if defined(BOARD_HAS_PSRAM) && BOARD_HAS_PSRAM == 1
	try {
		_data = std::allocate_shared<Data>(s_data_alloc_seed);
	}
	catch (const std::bad_alloc&) {
		ERROR("Bytes failed to allocate empty data buffer (PSRAM)");
		throw std::runtime_error("Failed to allocate empty data buffer");
	}
	if (capacity > 0) {
		_data->reserve(capacity);
	}
#else
	Data* data = new Data();
	if (data == nullptr) {
		ERROR("Bytes failed to allocate empty data buffer");
		throw std::runtime_error("Failed to allocate empty data buffer");
	}
//MEM("newData: Created new data");
	if (capacity > 0) {
//MEMF("newData: Reserving data capacity of %u...", capacity);
		data->reserve(capacity);
//MEM("newData: Reserved data capacity");
	}
//MEM("newData: Assigning data to shared data pointer...");
	_data = SharedData(data);
//MEM("newData: Assigned data to shared data pointer");
#endif
	_exclusive = true;
}

// Ensures that instance has exclusive shared data
// - If instance has no shared data then create new shared data
// - If instance does not have exclusive on shared data that is not empty then make a copy of shared data (if requests) and reserve capacity (if requested)
// - If instance does not have exclusive on shared data that is empty then create new shared data
// - If instance already has exclusive on shared data then do nothing except reserve capacity (if requested)
void Bytes::exclusiveData(bool copy /*= true*/, size_t capacity /*= 0*/) {
	if (!_data) {
		newData(capacity);
	}
	else if (!_exclusive) {
		if (copy && !_data->empty()) {
#if defined(BOARD_HAS_PSRAM) && BOARD_HAS_PSRAM == 1
			SharedData fresh;
			try {
				fresh = std::allocate_shared<Data>(s_data_alloc_seed);
			}
			catch (const std::bad_alloc&) {
				ERROR("Bytes failed to duplicate data buffer (PSRAM)");
				throw std::runtime_error("Failed to duplicate data buffer");
			}
			if (capacity > 0) {
				fresh->reserve((capacity > _data->size()) ? capacity : _data->size());
			}
			else {
				fresh->reserve(_data->size());
			}
			fresh->insert(fresh->begin(), _data->begin(), _data->end());
			_data = fresh;
#else
			Data* data = new Data();
			if (data == nullptr) {
				ERROR("Bytes failed to duplicate data buffer");
				throw std::runtime_error("Failed to duplicate data buffer");
			}
			if (capacity > 0) {
				data->reserve((capacity > _data->size()) ? capacity : _data->size());
			}
			else {
				data->reserve(_data->size());
			}
			data->insert(data->begin(), _data->begin(), _data->end());
			_data = SharedData(data);
#endif
			_exclusive = true;
		}
		else {
//MEM("Bytes is creating its own data because shared is empty");
			//data = new Data();
			//if (data == nullptr) {
			//	ERROR("Bytes failed to allocate empty data buffer");
			//	throw std::runtime_error("Failed to allocate empty data buffer");
			//}
			//_data = SharedData(data);
			//_exclusive = true;
//MEM("exclusiveData: Creating new empty data...");
			newData(capacity);
//MEM("exclusiveData: Created new empty data");
		}
	}
	else if (capacity > 0 && capacity > size()) {
		reserve(capacity);
	}
}

int Bytes::compare(const Bytes& bytes) const {
	if (_data == bytes._data) {
		return 0;
	}
	else if (!_data) {
		return -1;
	}
	else if (!bytes._data) {
		return 1;
	}
	else if (*_data < *(bytes._data)) {
		return -1;
	}
	else if (*_data > *(bytes._data)) {
		return 1;
	}
	else {
		return 0;
	}
}

int Bytes::compare(const uint8_t* buf, size_t size) const {
	if (!_data && size == 0) {
		return 0;
	}
	else if (!_data) {
		return -1;
	}
	int cmp = memcmp(_data->data(), buf, (_data->size() < size) ? _data->size() : size);
	if (cmp == 0 && _data->size() < size) {
		return -1;
	}
	else if (cmp == 0 && _data->size() > size) {
		return 1;
	}
	return cmp;
}

void Bytes::assignHex(const uint8_t* hex, size_t hex_size) {
	// if assignment is empty then clear data and don't bother creating new
	if (hex == nullptr || hex_size <= 0) {
		_data = nullptr;
		_exclusive = true;
		return;
	}
	// Truncate to even length (hex bytes come in pairs)
	hex_size &= ~(size_t)1;
	if (hex_size == 0) {
		_data = nullptr;
		_exclusive = true;
		return;
	}
	exclusiveData(false, hex_size / 2);
	// need to clear data since we're appending below
	_data->clear();
	for (size_t i = 0; i < hex_size; i += 2) {
		uint8_t byte = (hex[i] % 32 + 9) % 25 * 16 + (hex[i+1] % 32 + 9) % 25;
		_data->push_back(byte);
	}
}

void Bytes::appendHex(const uint8_t* hex, size_t hex_size) {
	// if append is empty then do nothing
	if (hex == nullptr || hex_size <= 0) {
		return;
	}
	// Truncate to even length (hex bytes come in pairs)
	hex_size &= ~(size_t)1;
	if (hex_size == 0) {
		return;
	}
	exclusiveData(true, size() + (hex_size / 2));
	for (size_t i = 0; i < hex_size; i += 2) {
		uint8_t byte = (hex[i] % 32 + 9) % 25 * 16 + (hex[i+1] % 32 + 9) % 25;
		_data->push_back(byte);
	}
}

const char hex_upper_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
const char hex_lower_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

std::string RNS::hexFromByte(uint8_t byte, bool upper /*= true*/) {
	std::string hex;
	if (upper) {
		hex += hex_upper_chars[ (byte&  0xF0) >> 4];
		hex += hex_upper_chars[ (byte&  0x0F) >> 0];
	}
	else {
		hex += hex_lower_chars[ (byte&  0xF0) >> 4];
		hex += hex_lower_chars[ (byte&  0x0F) >> 0];
	}
	return hex;
}

std::string Bytes::toHex(bool upper /*= false*/) const {
	if (!_data) {
		return "";
	}
	std::string hex;
	for (uint8_t byte : *_data) {
		if (upper) {
			hex += hex_upper_chars[ (byte&  0xF0) >> 4];
			hex += hex_upper_chars[ (byte&  0x0F) >> 0];
		}
		else {
			hex += hex_lower_chars[ (byte&  0xF0) >> 4];
			hex += hex_lower_chars[ (byte&  0x0F) >> 0];
		}
	}
	return hex;
}

// mid
Bytes Bytes::mid(size_t beginpos, size_t len) const {
	if (!_data || beginpos >= size()) {
		return NONE;
	}
	size_t remaining = size() - beginpos;
	if (len > remaining) {
		len = remaining;
	}
	return {data() + beginpos, len};
}

// to end
Bytes Bytes::mid(size_t beginpos) const {
	if (!_data || beginpos >= size()) {
		return NONE;
	}
	 return {data() + beginpos, size() - beginpos};
}
