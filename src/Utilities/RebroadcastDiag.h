/*
 * Rebroadcast allocation diagnostic (build-flag gated: URTN_REBROADCAST_DIAG).
 *
 * Pinpoints the announce re-broadcast SRAM leak by tracking the live (alloc'd
 * but not yet freed) count of the three object types in the path, keyed by the
 * announce destination hash so a single announce's lifecycle can be followed.
 *
 * It is a FIXED-SIZE array with ZERO dynamic allocation, so the instrumentation
 * itself cannot leak. Aggregate alloc/free counts are exact (uint counters);
 * the per-object live table is capped (MAX_LIVE) — overflow is counted, not
 * grown. All mutation is under a FreeRTOS critical section (ctors/dtors run on
 * loopTask, the diag snapshot reads from the async webserver task).
 */
#pragma once

#if defined(URTN_REBROADCAST_DIAG)

#include <stdint.h>
#include <stddef.h>
#include "../Bytes.h"

#if defined(ESP32)
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#endif

namespace RNS {

	class RebroadcastDiag {
	public:
		enum Site : uint8_t { SITE_ENTRY = 0, SITE_DEST = 1, SITE_PACKET = 2, NUM_SITES = 3 };
		static constexpr int MAX_LIVE = 384;   // ~3 KB fixed; bounds the instrumentation

		struct Live {
			const void* ptr;
			uint8_t     site;
			uint8_t     hash[6];   // destination-hash prefix, enough to identify the announce
		};

		static void on_alloc(Site site, const void* ptr, const Bytes& hash) {
			enter();
			s_allocs[site]++;
			if (s_live_count < MAX_LIVE) {
				Live& L = s_live[s_live_count++];
				L.ptr = ptr; L.site = site;
				size_t n = hash.size() < 6 ? hash.size() : 6;
				for (size_t i = 0; i < 6; i++) L.hash[i] = (i < n) ? hash.data()[i] : 0;
			}
			else {
				s_overflow++;
			}
			exit();
		}

		// Free is matched by pointer only: the Object dtor knows `this` but not
		// which site tagged it. No-op (counted as untracked) if the pointer was
		// never tagged here, so it is safe to call from the generic Object dtors.
		static void on_free(const void* ptr) {
			enter();
			for (uint16_t i = 0; i < s_live_count; i++) {
				if (s_live[i].ptr == ptr) {
					s_frees[s_live[i].site]++;
					s_live[i] = s_live[--s_live_count];   // swap-with-last removal
					exit();
					return;
				}
			}
			s_untracked_frees++;
			exit();
		}

		static uint32_t allocs(Site s) { return s_allocs[s]; }
		static uint32_t frees(Site s)  { return s_frees[s]; }
		static int32_t  live(Site s)   { return (int32_t)s_allocs[s] - (int32_t)s_frees[s]; }
		static uint32_t overflow()        { return s_overflow; }
		static uint32_t untracked_frees() { return s_untracked_frees; }
		static uint16_t live_count()      { return s_live_count; }

		// Copy up to `max` live entries into caller-provided storage (memcpy under
		// lock, NO allocation), returns count copied. The caller formats JSON
		// outside the critical section.
		static int snapshot(Live* out, int max) {
			enter();
			int n = (s_live_count < max) ? s_live_count : max;
			for (int i = 0; i < n; i++) out[i] = s_live[i];
			exit();
			return n;
		}

	private:
		static inline void enter() {
#if defined(ESP32)
			taskENTER_CRITICAL(&s_mux);
#endif
		}
		static inline void exit() {
#if defined(ESP32)
			taskEXIT_CRITICAL(&s_mux);
#endif
		}

		static inline uint32_t s_allocs[NUM_SITES] = {0, 0, 0};
		static inline uint32_t s_frees[NUM_SITES]  = {0, 0, 0};
		static inline uint32_t s_overflow = 0;
		static inline uint32_t s_untracked_frees = 0;
		static inline uint16_t s_live_count = 0;
		static inline Live     s_live[MAX_LIVE] = {};
#if defined(ESP32)
		static inline portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
#endif
	};

	static const char* const REBROADCAST_DIAG_SITE_NAMES[3] = { "announce_entry", "retx_dest", "retx_packet" };

}

#endif // URTN_REBROADCAST_DIAG
