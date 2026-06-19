# Upstream divergence ledger

This fork (`ur-patches`) of [Reticulum](https://github.com/markqvist/Reticulum)
deliberately behaves differently from upstream RNS in a few places, driven by
the constraints of the memory-limited, single-threaded ESP32 firmware that
consumes it (microReticulum_Firmware / uRSupreme).

Rules:

- Any commit that introduces or removes a divergence updates this file in the
  same commit, and marks the code with a `DIVERGES:` comment giving the reason.
- Every entry cites the code and its upstream counterpart, with the reason.
- A divergence is deliberate and minimal. Where the port can match upstream it
  does; these are the places it structurally cannot on the target.

## Active divergences

### 1. Receiver flow control is bounded by in-flight BYTES, not parts
- Where: `src/Type.h` (`RECV_MAX_INFLIGHT_BYTES`), `src/ResourceData.h`
  (`_window_cap`), `src/Resource.cpp` (`accept`, `send_part_request`, the
  window-growth ramp in `on_part`).
- Upstream: the request window is a PART count that ramps to
  `WINDOW_MAX_FAST = 75` (`Resource.py`), sized for hosts that can buffer a
  whole fast-link window.
- Why: on a fast link with a large SDU (a TCP backbone negotiates an ~8 KiB
  MTU), 75 parts is ~600 KiB in flight, which overruns this receiver: parts
  arrive faster than it can drain and persist them, the sender's interface
  outbound buffer overflows, and the transfer stalls. Capping the window by
  in-flight bytes makes the receiver advertise its true capacity regardless of
  SDU, so RNS's own receiver-driven window paces the sender with no
  sender-side throttle. On a small-SDU LoRa link the part cap binds first and
  this never engages.

### 2. Receive part-writes can be deferred off the caller's task
- Where: `src/ResourceBuffer.h` / `src/ResourceBuffer.cpp`
  (`set_part_write_hook`, `part_writes_deferred`, `FlashResourceBuffer::open`
  and `::write_part`).
- Upstream: `Resource` writes each received part to its buffer inline as it
  arrives.
- Why: on the firmware these writes hit the SD card, which shares a bus with
  the radio and can stall for seconds. Run inline on the single-threaded main
  loop they freeze the radio and the request flow. When the firmware registers
  a part-write hook, `write_part` copies the part and hands `(path, offset,
  bytes)` to the hook instead; a firmware worker performs the SD write
  off-loop. With no hook registered the write is inline (upstream behaviour).
  In deferred mode `open()` keeps no microStore file handle so the worker owns
  all file I/O for that buffer via raw POSIX — a second open handle on the same
  file corrupted transfers on this hardware (FATFS-via-VFS).

### 3. Receive conclude (read-back + decrypt + verify) can be deferred
- Where: `src/Resource.h` / `src/Resource.cpp` (`set_conclude_deferrer`,
  `prepare_from_assembled`, `detach_buffer`, `reattach_buffer`,
  `deliver_assembly`, the deferral branch in `on_part`, the `_prepared` path in
  `_assemble_and_deliver`), `src/ResourceData.h` (`_prepared*`,
  `_prepared_seg_plaintext`, `_pending_proof`), `src/ResourceBuffer`
  (`read_next`).
- Upstream: `Resource.assemble()` re-reads the assembled blob, decrypts and
  verifies it, and fires the application callback synchronously from the
  receive path (`Resource.py`).
- Why: that whole unit (a whole-transfer SD read + decrypt) runs on the
  firmware's main loop and scales with transfer size (seconds for a multi-MiB
  attachment), starving the radio. When the firmware registers a conclude
  deferrer, `on_part` hands a disk-backed segment's read+decrypt+verify to a
  worker; the worker stashes the plaintext + proof and the main loop then runs
  only the RNS-mutating delivery. The deferrer holds a `Resource` copy
  (shared_ptr keep-alive); a resource cancelled while preparing is dropped by a
  status guard in `deliver_assembly`. With no deferrer the conclude is inline
  (upstream behaviour). Split (multi-segment) transfers defer each segment the
  same way; the per-segment store append and the final whole-store readback
  remain on the loop (watchdog-guarded).

## Diagnostics (not divergences)

`src/SdReadStat.h` adds resource-transfer SD-read timing and a receive-flow
snapshot (window / parts / outstanding / requests / timeouts) that the firmware
surfaces on `/api/diag/storage`. It only reads state; it changes no behaviour.
