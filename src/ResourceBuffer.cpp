/*
 * ResourceBuffer implementation. See ResourceBuffer.h for the contract.
 */

#include "ResourceBuffer.h"

#include "Type.h"
#include "Log.h"
#include "Utilities/OS.h"

#include <SHA256.h>

#include <cstring>

using namespace RNS;
using namespace RNS::Utilities;

namespace {

// Process-wide pending-bytes counter for flash-backed buffers. Single-threaded
// tick model in this codebase; no atomic needed.
size_t g_flash_pending_bytes = 0;

// Directory under which FlashResourceBuffer creates temp files. Default is
// populated lazily from Reticulum's storagepath if not explicitly set.
std::string g_resource_tmp_path;

// Optional per-open() resolver; SD-aware in the firmware. When set,
// returns the directory for the current allocation; when null, the
// static path above is used.
ResourceTmpPathResolver g_resource_tmp_path_resolver = nullptr;

// Optional resolver consulted on each receive-cap check. Replaces the
// static Type::Resource::FIRMWARE_MAX_INCOMING with a runtime value
// driven by the firmware's StorageConfig.
ResourceMaxIncomingResolver g_resource_max_incoming_resolver = nullptr;

// Monotonic counter to ensure temp filenames are unique within a boot.
uint64_t g_resource_tmp_counter = 0;

const char* current_tmp_path() {
    if (g_resource_tmp_path_resolver) {
        const char* p = g_resource_tmp_path_resolver();
        if (p && *p) return p;
    }
    if (g_resource_tmp_path.empty()) {
        // We can't depend on Reticulum::storagepath() here without
        // coupling Reticulum.h, so default to a hidden directory at the
        // FS root that the firmware is expected to override via
        // set_resource_tmp_path[_resolver] if it wants something inside
        // its own storage tree.
        g_resource_tmp_path = "/resources_tmp";
    }
    return g_resource_tmp_path.c_str();
}

bool ensure_tmp_dir_exists() {
    const char* dir = current_tmp_path();
    try {
        if (OS::directory_exists(dir)) return true;
        return OS::create_directory(dir);
    }
    catch (const std::exception& e) {
        ERRORF("ResourceBuffer: failed to create tmp dir '%s': %s",
               dir, e.what());
        return false;
    }
}

}  // anonymous namespace


// ---------------- HeapResourceBuffer ----------------

bool HeapResourceBuffer::open(size_t total_size) {
    if (_open) {
        WARNING("HeapResourceBuffer::open called twice");
        return false;
    }
    if (total_size == 0) return false;

    // Allocate a fully-sized buffer pre-zeroed. Bytes::writable() reserves
    // and resizes; we zero it manually so gaps between out-of-order parts
    // read back as zeros rather than uninitialised heap.
    uint8_t* p = _data.writable(total_size);
    if (p == nullptr) {
        ERRORF("HeapResourceBuffer::open: alloc failed for %zu bytes", total_size);
        return false;
    }
    std::memset(p, 0, total_size);

    _total_size = total_size;
    _open = true;
    return true;
}

bool HeapResourceBuffer::write_part(uint16_t part_index, uint16_t sdu,
                                    const Bytes& part_data) {
    if (!_open) return false;
    const size_t offset = static_cast<size_t>(part_index) * static_cast<size_t>(sdu);
    if (offset >= _total_size) {
        ERRORF("HeapResourceBuffer::write_part: offset %zu beyond total %zu",
               offset, _total_size);
        return false;
    }
    const size_t copy_bytes = std::min(part_data.size(), _total_size - offset);
    uint8_t* dst = _data.writable(_total_size);
    if (dst == nullptr) return false;
    std::memcpy(dst + offset, part_data.data(), copy_bytes);
    return true;
}

Bytes HeapResourceBuffer::read_all() {
    if (!_open) return Bytes();
    return _data;
}

Bytes HeapResourceBuffer::compute_sha256() {
    if (!_open) return Bytes();
    SHA256 digest;
    digest.reset();
    digest.update(_data.data(), _data.size());
    Bytes out;
    digest.finalize(out.writable(32), 32);
    return out;
}

void HeapResourceBuffer::discard() {
    _data = Bytes();
    _total_size = 0;
    _open = false;
}


// ---------------- FlashResourceBuffer ----------------

bool FlashResourceBuffer::open(size_t total_size) {
    if (_open) {
        WARNING("FlashResourceBuffer::open called twice");
        return false;
    }
    if (total_size == 0) return false;
    if (!flash_quota_can_allocate(total_size)) {
        WARNINGF("FlashResourceBuffer::open: would exceed flash quota "
                 "(pending=%zu, requesting=%zu, cap=%u)",
                 g_flash_pending_bytes, total_size,
                 (unsigned)Type::Resource::FLASH_QUOTA_BYTES);
        return false;
    }
    if (!ensure_tmp_dir_exists()) return false;

    // Build a unique temp path: <tmp_dir>/res_<ltime_ms>_<counter>.bin
    // Path resolved per-open() — SD-aware in the firmware via the
    // optional ResourceTmpPathResolver, falling back to the static
    // path otherwise. Picks up mid-session SD insert/eject.
    char path[256];
    snprintf(path, sizeof(path), "%s/res_%llu_%llu.bin",
             current_tmp_path(),
             (unsigned long long)OS::ltime(),
             (unsigned long long)(++g_resource_tmp_counter));
    _temp_path = path;

    try {
        _file = OS::open_file(_temp_path.c_str(), microStore::File::ModeReadWrite);
    }
    catch (const std::exception& e) {
        ERRORF("FlashResourceBuffer::open: open_file failed: %s", e.what());
        return false;
    }
    if (!_file) {
        ERRORF("FlashResourceBuffer::open: file handle invalid for '%s'", _temp_path.c_str());
        return false;
    }

    _total_size = total_size;
    g_flash_pending_bytes += total_size;
    _open = true;
    DEBUGF("FlashResourceBuffer: opened '%s' total=%zu pending=%zu",
           _temp_path.c_str(), _total_size, g_flash_pending_bytes);
    return true;
}

bool FlashResourceBuffer::write_part(uint16_t part_index, uint16_t sdu,
                                     const Bytes& part_data) {
    if (!_open || !_file) return false;
    const size_t offset = static_cast<size_t>(part_index) * static_cast<size_t>(sdu);
    if (offset >= _total_size) {
        ERRORF("FlashResourceBuffer::write_part: offset %zu beyond total %zu",
               offset, _total_size);
        return false;
    }
    const size_t copy_bytes = std::min(part_data.size(), _total_size - offset);

    if (_file.seek((uint32_t)offset, microStore::SeekModeSet) < 0) {
        ERRORF("FlashResourceBuffer::write_part: seek to %zu failed", offset);
        return false;
    }
    const size_t wrote = _file.write(part_data.data(), copy_bytes);
    if (wrote != copy_bytes) {
        ERRORF("FlashResourceBuffer::write_part: wrote %zu of %zu bytes",
               wrote, copy_bytes);
        return false;
    }
    _file.flush();
    return true;
}

Bytes FlashResourceBuffer::read_all() {
    if (!_open || !_file) return Bytes();
    Bytes out;
    uint8_t* dst = out.writable(_total_size);
    if (dst == nullptr) return Bytes();
    if (_file.seek(0, microStore::SeekModeSet) < 0) return Bytes();

    size_t total_read = 0;
    while (total_read < _total_size) {
        const size_t want = _total_size - total_read;
        const size_t n = _file.read(dst + total_read, want);
        if (n == 0 || n == (size_t)-1) break;
        total_read += n;
    }
    if (total_read != _total_size) {
        ERRORF("FlashResourceBuffer::read_all: read %zu of %zu bytes",
               total_read, _total_size);
        out.resize(total_read);
    }
    return out;
}

Bytes FlashResourceBuffer::compute_sha256() {
    if (!_open || !_file) return Bytes();
    if (_file.seek(0, microStore::SeekModeSet) < 0) return Bytes();

    SHA256 digest;
    digest.reset();
    uint8_t chunk[1024];
    size_t total_read = 0;
    while (total_read < _total_size) {
        const size_t want = std::min(sizeof(chunk), _total_size - total_read);
        const size_t n = _file.read(chunk, want);
        if (n == 0 || n == (size_t)-1) break;
        digest.update(chunk, n);
        total_read += n;
    }
    Bytes out;
    digest.finalize(out.writable(32), 32);
    return out;
}

bool FlashResourceBuffer::commit_to(const char* destination_path) {
    if (!_open || _committed) return false;
    _file.close();
    const bool ok = OS::rename_file(_temp_path.c_str(), destination_path);
    if (!ok) {
        ERRORF("FlashResourceBuffer::commit_to: rename '%s' -> '%s' failed",
               _temp_path.c_str(), destination_path);
        return false;
    }
    if (g_flash_pending_bytes >= _total_size) g_flash_pending_bytes -= _total_size;
    _committed = true;
    _open = false;
    return true;
}

void FlashResourceBuffer::discard() {
    if (!_open && !_committed) return;
    if (_file) _file.close();
    if (!_committed && !_temp_path.empty()) {
        try { OS::remove_file(_temp_path.c_str()); }
        catch (const std::exception& e) {
            WARNINGF("FlashResourceBuffer::discard: remove '%s' failed: %s",
                     _temp_path.c_str(), e.what());
        }
        if (g_flash_pending_bytes >= _total_size) g_flash_pending_bytes -= _total_size;
    }
    _total_size = 0;
    _open = false;
    _temp_path.clear();
}


// ---------------- factory + globals ----------------

std::unique_ptr<ResourceBuffer> RNS::make_resource_buffer(size_t transfer_size) {
    if (transfer_size <= Type::Resource::RAM_BUFFER_THRESHOLD) {
        return std::unique_ptr<ResourceBuffer>(new HeapResourceBuffer());
    }
    if (!flash_quota_can_allocate(transfer_size)) {
        WARNINGF("make_resource_buffer: flash quota would be exceeded "
                 "(pending=%zu, requesting=%zu)",
                 g_flash_pending_bytes, transfer_size);
        return nullptr;
    }
    return std::unique_ptr<ResourceBuffer>(new FlashResourceBuffer());
}

size_t RNS::flash_quota_pending_bytes() {
    return g_flash_pending_bytes;
}

bool RNS::flash_quota_can_allocate(size_t additional_bytes) {
    return (g_flash_pending_bytes + additional_bytes) <= Type::Resource::FLASH_QUOTA_BYTES;
}

void RNS::set_resource_tmp_path(const char* directory_path) {
    if (directory_path == nullptr) return;
    g_resource_tmp_path = directory_path;
}

const char* RNS::resource_tmp_path() {
    // Force evaluation of any resolver / default through the same path
    // used at open() time so callers see consistent results.
    return current_tmp_path();
}

void RNS::set_resource_tmp_path_resolver(ResourceTmpPathResolver resolver) {
    g_resource_tmp_path_resolver = resolver;
}

void RNS::set_resource_max_incoming_resolver(ResourceMaxIncomingResolver resolver) {
    g_resource_max_incoming_resolver = resolver;
}

size_t RNS::resource_max_incoming() {
    if (g_resource_max_incoming_resolver) {
        const size_t v = g_resource_max_incoming_resolver();
        if (v > 0) return v;
    }
    return (size_t)Type::Resource::FIRMWARE_MAX_INCOMING;
}
