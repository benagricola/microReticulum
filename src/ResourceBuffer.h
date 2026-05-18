/*
 * ResourceBuffer — receive-side payload store for in-flight Resources.
 *
 * Hybrid storage: small resources buffer in RAM, large ones spill to a
 * temp file on flash so the heap doesn't blow up. The factory picks the
 * implementation based on the resource's advertised transfer size against
 * Type::Resource::RAM_BUFFER_THRESHOLD. Flash-backed buffers are accounted
 * against a process-wide quota (Type::Resource::FLASH_QUOTA_BYTES) so a
 * flood of large resources can't fill the SPI flash.
 *
 * Sender-side parts are kept in a plain std::vector<Bytes> by Resource
 * itself; this class is receive-only.
 */

#pragma once

#include "Bytes.h"

#include <microStore/File.h>

#include <memory>
#include <string>

namespace RNS {

class ResourceBuffer {
public:
    virtual ~ResourceBuffer() = default;

    // Pre-allocate for a resource of `total_size` bytes. Returns false if
    // allocation / file open failed (heap exhausted, flash quota exceeded,
    // FS error).
    virtual bool open(size_t total_size) = 0;

    // Write `part_data` at offset `part_index * sdu`. Last part may be
    // shorter than sdu. Returns false on write failure.
    virtual bool write_part(uint16_t part_index, uint16_t sdu, const Bytes& part_data) = 0;

    // Read the full assembled buffer (call once after all parts are in).
    virtual Bytes read_all() = 0;

    // SHA-256 over the entire current content. For flash backends this
    // streams the file through the hash without loading it into RAM.
    virtual Bytes compute_sha256() = 0;

    // Release resources (delete temp file for flash backend). Idempotent.
    virtual void discard() = 0;

    virtual size_t total_size() const = 0;
    virtual bool   is_flash_backed() const = 0;
};


class HeapResourceBuffer : public ResourceBuffer {
public:
    HeapResourceBuffer() = default;
    ~HeapResourceBuffer() override { discard(); }

    bool   open(size_t total_size) override;
    bool   write_part(uint16_t part_index, uint16_t sdu, const Bytes& part_data) override;
    Bytes  read_all() override;
    Bytes  compute_sha256() override;
    void   discard() override;
    size_t total_size() const override { return _total_size; }
    bool   is_flash_backed() const override { return false; }

private:
    Bytes  _data;
    size_t _total_size = 0;
    bool   _open       = false;
};


class FlashResourceBuffer : public ResourceBuffer {
public:
    FlashResourceBuffer() = default;
    ~FlashResourceBuffer() override { discard(); }

    bool   open(size_t total_size) override;
    bool   write_part(uint16_t part_index, uint16_t sdu, const Bytes& part_data) override;
    Bytes  read_all() override;
    Bytes  compute_sha256() override;
    void   discard() override;
    size_t total_size() const override { return _total_size; }
    bool   is_flash_backed() const override { return true; }

    // Take ownership of the temp file by renaming it into a destination
    // path; the temp file no longer exists after a successful commit, and
    // discard() becomes a no-op. Returns false on rename failure (caller
    // should fall back to read_all()-then-write).
    bool   commit_to(const char* destination_path);

    const char* temp_path() const { return _temp_path.c_str(); }

private:
    std::string         _temp_path;
    microStore::File    _file;
    size_t              _total_size = 0;
    bool                _open       = false;
    bool                _committed  = false;
};


// Pick HeapResourceBuffer for transfer_size <= RAM_BUFFER_THRESHOLD, else
// FlashResourceBuffer. Returns nullptr if the flash quota is exceeded for
// a flash-bound allocation. Caller must call open() after — the factory
// only chooses the implementation.
std::unique_ptr<ResourceBuffer> make_resource_buffer(size_t transfer_size);


// Static accounting for the flash quota. Returns the current pending byte
// count and whether a new allocation of `additional_bytes` would fit. Each
// FlashResourceBuffer::open() / discard() updates this; callers can also
// query at ADV time without allocating a buffer.
size_t flash_quota_pending_bytes();
bool   flash_quota_can_allocate(size_t additional_bytes);


// Configure the directory used for flash temp files. Default is
// "<reticulum_storagepath>/resources_tmp". The firmware can override at
// boot if it wants a different mount point.
void set_resource_tmp_path(const char* directory_path);
const char* resource_tmp_path();

// Optional resolver consulted per-FlashResourceBuffer::open(). When set,
// returns the directory to use for that specific allocation; when null,
// the static path from set_resource_tmp_path() (or its default) is used.
// Firmware uses this for SD-aware routing: "/sd/lxmf_resource_tmp" when
// the card is mounted, "/lxmf_resource_tmp" when it isn't. The resolver
// is consulted at allocation time rather than once at boot so mid-session
// card insert/eject is honoured on the next transfer.
//
// The directory itself must exist before open() runs — firmware should
// pre-create both candidate paths at boot since microReticulum's
// OS::create_directory only knows about microStore filesystem, not SD.
using ResourceTmpPathResolver = const char* (*)();
void set_resource_tmp_path_resolver(ResourceTmpPathResolver resolver);

// Optional resolver consulted whenever the receiver evaluates whether
// to accept an inbound Resource. When set, returns the largest
// per-resource size the firmware will currently accept; receivers
// compare an ADV's transfer_size against this. When null,
// Type::Resource::FIRMWARE_MAX_INCOMING (the raw protocol ceiling) is
// used. Firmware installs a resolver that returns
// Web::Storage::effective_max_receive() so the user-facing cap
// dominates without recompiling.
using ResourceMaxIncomingResolver = size_t (*)();
void set_resource_max_incoming_resolver(ResourceMaxIncomingResolver resolver);
size_t resource_max_incoming();

}  // namespace RNS
