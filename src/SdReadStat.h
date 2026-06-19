#pragma once
#include <stdint.h>

// Resource-transfer SD-read timing + receive-flow diagnostics. Isolates the
// SD-read time on the resource transfer paths (send: Resource::_load_part,
// receive: FlashResourceBuffer::read_all) from decrypt/CPU, and snapshots the
// in-progress incoming Resource's window/part state so a receive stall is
// attributable. With an SD card present the resource-tmp + receive buffer spill
// live under /sd, so on a carded device these are SD reads; without a card they
// are LittleFS reads. Since-boot maxima + counts, reset via POST
// /api/diag/storage.
#if defined(ESP32)
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <string.h>
#endif

namespace RNS { namespace SdReadStat {
  inline uint32_t& loadpart_max_us() { static uint32_t v = 0; return v; }  // worst single _load_part read (open+seek+read+close)
  inline uint32_t& loadpart_count()  { static uint32_t v = 0; return v; }
  inline uint32_t& readall_max_us()  { static uint32_t v = 0; return v; }  // worst read_all (whole transfer, one pass)
  inline uint32_t& readall_count()   { static uint32_t v = 0; return v; }
  inline uint64_t& total_bytes()     { static uint64_t v = 0; return v; }
  inline uint32_t& over10ms()        { static uint32_t v = 0; return v; }  // single reads > 10 ms
  inline uint32_t& over100ms()       { static uint32_t v = 0; return v; }  // single reads > 100 ms
  // Receive-flow diagnostics: snapshot of the in-progress incoming
  // Resource so a stall is attributable (received vs parts, window, retries).
  inline uint16_t& rx_received()    { static uint16_t v = 0; return v; }   // _received_count
  inline uint16_t& rx_parts()       { static uint16_t v = 0; return v; }   // _parts_count
  inline uint16_t& rx_outstanding() { static uint16_t v = 0; return v; }   // _outstanding_parts
  inline uint16_t& rx_window()      { static uint16_t v = 0; return v; }   // _window
  inline int32_t&  rx_cch()         { static int32_t v = 0; return v; }    // _consecutive_completed_height
  inline uint32_t& rx_reqs()        { static uint32_t v = 0; return v; }   // send_part_request calls
  inline uint32_t& rx_timeouts()    { static uint32_t v = 0; return v; }   // window_timeout retries
  inline uint32_t& rx_last_wtmo_ms(){ static uint32_t v = 0; return v; }   // last computed window_timeout (ms)
  inline double&   rx_eifr()        { static double v = 0; return v; }     // last _eifr_bps

  inline void reset() {
    loadpart_max_us() = 0; loadpart_count() = 0;
    readall_max_us()  = 0; readall_count()  = 0;
    total_bytes() = 0; over10ms() = 0; over100ms() = 0;
  }

#if defined(ESP32)
  inline int64_t now_us() { return esp_timer_get_time(); }
#else
  inline int64_t now_us() { return 0; }
#endif

  // Record one read of duration dt_us covering `bytes`, into the given slot.
  inline void record(uint32_t& max_slot, uint32_t& cnt, uint32_t dt_us, uint32_t bytes) {
    if (dt_us > max_slot) max_slot = dt_us;
    cnt++;
    total_bytes() += bytes;
    if (dt_us > 100000) over100ms()++;
    else if (dt_us > 10000) over10ms()++;
  }
}}
