# HexCore Zero-Copy IPC Architecture — SharedArrayBuffer Design for v4.0.0

## Executive Summary

Zero-copy IPC (Inter-Process Communication) is a memory optimization technique that eliminates unnecessary data copying between JavaScript and native C++ code. In the context of HexCore's malware analysis platform, this is particularly critical for emulation workloads where the Unicorn engine executes millions of instructions per second.

**Why it matters:**
- Current bottleneck: ~50K instructions/sec (Unicorn with N-API copy overhead during hooks)
- Target performance: 10M+ instructions/sec (zero-copy hooks)
- Potential speedup: **~200x** for emulation-heavy workloads

The current architecture copies data via `std::vector<uint8_t>` for every native call, resulting in O(n) overhead where n is the data size. For emulation hooks that trigger on every memory access or instruction execution, this overhead becomes the dominant cost.

---

## Current Architecture

### Data Flow Today

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   TypeScript    │     │     N-API        │     │   C++ Native    │
│                 │     │   (NAPI_VERSION  │     │                 │
│   Buffer        │────▶│       8)         │────▶│  std::vector    │
│   (JS Heap)     │copy │                  │copy │  (C++ Heap)     │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                          │
                                                          ▼
                                                   ┌─────────────────┐
                                                   │   Processing    │
                                                   │   (Remill,      │
                                                   │   Capstone,     │
                                                   │   Unicorn)      │
                                                   └─────────────────┘
                                                          │
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   TypeScript    │     │     N-API        │     │   C++ Native    │
│                 │     │                  │     │                 │
│   new Buffer    │◀────│   Buffer::New    │◀────│   Result data   │
│   (JS Heap)     │copy │                  │copy │  (C++ Heap)     │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

### Overhead Analysis

| Operation | Copies | Complexity | Typical Size |
|-----------|--------|------------|--------------|
| PE header parse | 2 | O(n) | 4KB |
| Disassembly block | 2 | O(n) | 1KB-64KB |
| Unicorn hook (mem read) | 2 | O(n) | 1-8 bytes |
| Unicorn hook (code exec) | 2 | O(n) | 16 bytes |
| Remill IR lift | 2 | O(n) | 256B-4KB |

**Critical observation:** For Unicorn emulation hooks, the data size is small (1-16 bytes), but the call frequency is extremely high (millions of times per second). The fixed overhead of buffer allocation and copying dominates.

### Reference Implementation

The `remill_wrapper.cpp` in hexcore-remill uses NAPI_VERSION=8:

```cpp
// Current pattern (remill_wrapper.cpp)
Napi::Buffer<uint8_t> inputBuffer = info[0].As<Napi::Buffer<uint8_t>>();
std::vector<uint8_t> inputData(inputBuffer.Data(),
                               inputBuffer.Data() + inputBuffer.Length());
// Process inputData...
// Copy results back to new Buffer
return Napi::Buffer<uint8_t>::Copy(env, result.data(), result.size());
```

---

## Proposed Architecture

### SharedArrayBuffer Approach

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Shared Memory Region                             │
│  ┌─────────────┬─────────────────────────────────────────────────┐  │
│  │   Header    │                  Data Payload                    │  │
│  │  (64 bytes) │              (configurable size)                 │  │
│  │             │                                                  │  │
│  │ [lockFlag   │  ┌───────────────────────────────────────────┐   │  │
│  │  dataSize   │  │   Direct pointer access from C++          │   │  │
│  │  status     │  │   No copying required!                    │   │  │
│  │  ...]       │  └───────────────────────────────────────────┘   │  │
│  └─────────────┴─────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
         ▲                                    ▲
         │                                    │
    ┌────┴────┐                          ┌────┴────┐
    │   JS    │◀── Atomics.wait/notify ─▶│ Worker  │
    │ Thread  │    (synchronization)     │ Thread  │
    └────┬────┘                          └────┬────┘
         │                                    │
         │    ┌────────────────────────┐      │
         └───▶│  Napi::ArrayBuffer     │◀─────┘
              │  (direct pointer access)      │
              └────────────────────────┘
```

### Key Components

1. **SharedArrayBuffer Allocation**
   - JS: `new SharedArrayBuffer(size)`
   - C++: `Napi::ArrayBuffer::New(env, externalData, size)` (zero-copy)

2. **Direct Memory Access**
   ```cpp
   // C++ side - no copy!
   Napi::ArrayBuffer ab = info[0].As<Napi::ArrayBuffer>();
   void* data = ab.Data();        // direct pointer
   size_t len = ab.ByteLength();  // size
   ```

3. **Synchronization via Atomics**
   ```javascript
   // JS side
   const lockFlag = new Int32Array(sharedBuffer, 0, 1);
   Atomics.wait(lockFlag, 0, 1);  // wait if locked
   Atomics.store(lockFlag, 0, 1); // acquire lock
   // ... use shared data ...
   Atomics.store(lockFlag, 0, 0); // release lock
   Atomics.notify(lockFlag, 0);   // notify waiters
   ```

4. **Header Layout**
   ```c
   struct SharedBufferHeader {
       int32_t  lockFlag;      // 0 = unlocked, 1 = locked
       uint32_t dataSize;      // actual data size in payload
       int32_t  status;        // operation status code
       uint32_t sequenceId;    // for ordering
       uint64_t timestamp;     // for debugging
       // 40 bytes padding to 64-byte cache line alignment
   };
   ```

### Threading Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    Electron Main Process                        │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │  UI Thread  │    │  Extension  │    │   Native Worker     │  │
│  │  (Renderer) │◀──▶│   Host      │◀──▶│   Thread (N-API)    │  │
│  │             │    │             │    │                     │  │
│  │ JS context  │    │ Message     │    │ Unicorn/Remill      │  │
│  │ with SAB    │    │ passing     │    │ direct SAB access   │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
│         ▲                                    ▲                  │
│         │         SharedArrayBuffer          │                  │
│         └────────────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Affected Extensions

All native N-API extensions require refactoring to support zero-copy IPC:

### Priority 1: High Impact (Emulation)

| Extension | Current Pattern | Impact | Effort |
|-----------|----------------|--------|--------|
| **hexcore-unicorn** | Buffer copy per hook | **Critical** - 200x speedup potential | High |
| **hexcore-remill** | std::vector for IR/data | High - frequent lifting calls | Medium |

### Priority 2: Medium Impact (Analysis)

| Extension | Current Pattern | Impact | Effort |
|-----------|----------------|--------|--------|
| **hexcore-capstone** | Buffer copy per disasm | Medium - batch operations | Medium |
| **hexcore-llvm-mc** | Buffer for machine code | Medium - encoding overhead | Low |

### Priority 3: Lower Impact (Storage/Utility)

| Extension | Current Pattern | Impact | Effort |
|-----------|----------------|--------|--------|
| **hexcore-better-sqlite3** | Buffer for blob data | Low - I/O bound | Low |
| **hexcore-souper** | std::vector for candidates | Low - compute bound | Medium |
| **hexcore-helix** | MLIR buffer handling | Medium - IR passes | High |
| **hexcore-pathfinder** | CFG data structures | Low - graph operations | Medium |

### Refactoring Requirements per Extension

#### hexcore-unicorn (Critical)
- Hook callbacks currently receive copied data
- Must switch to direct SAB pointer access
- Requires thread-safe hook registration
- Estimated LOC changed: ~500

#### hexcore-remill (High)
- `DecodeInstruction()` assumes owned memory
- Need variant that accepts external buffer
- LLVM Module generation can remain as-is
- Estimated LOC changed: ~300

#### hexcore-capstone (Medium)
- `cs_disasm()` accepts pointer + size
- Already compatible with SAB pattern
- Main change: avoid Buffer::Copy on results
- Estimated LOC changed: ~150

---

## Technical Blockers & Mitigations

### Blocker 1: Thread Safety

**Issue:** No current mutex protection on shared data structures.

**Mitigation:**
- Implement lock-free ring buffer for hook callbacks
- Use `Atomics` API for JS-side synchronization
- C++ side uses `std::atomic` for header fields
- Consider seqlock pattern for read-heavy workloads

```cpp
// Seqlock pattern for read-heavy hooks
class SeqLock {
    std::atomic<uint32_t> sequence_{0};

public:
    void write_lock() {
        sequence_.fetch_add(1);  // odd = write in progress
    }
    void write_unlock() {
        sequence_.fetch_add(1);  // even = write complete
    }
    bool read_begin(uint32_t& seq) {
        seq = sequence_.load();
        return (seq & 1) == 0;  // even = valid
    }
    bool read_end(uint32_t seq) {
        return sequence_.load() == seq;
    }
};
```

### Blocker 2: COOP/COEP Headers

**Issue:** SharedArrayBuffer requires cross-origin isolation in web contexts.

**Mitigation:**
- Electron: Set `webSecurity: true` with proper headers
- Add to main process:
  ```javascript
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Embedder-Policy': 'require-corp'
      }
    });
  });
  ```

### Blocker 3: Electron Support

**Issue:** SharedArrayBuffer needs explicit enable flag.

**Mitigation:**
- Add to Electron main process flags:
  ```javascript
  app.commandLine.appendSwitch('enable-features', 'SharedArrayBuffer');
  ```
- Verify in renderer: `typeof SharedArrayBuffer !== 'undefined'`

### Blocker 4: Remill Memory Assumptions

**Issue:** `DecodeInstruction()` assumes owned memory for lifetime of analysis.

**Mitigation:**
- Create `DecodeInstructionView()` variant taking `const uint8_t*, size_t`
- Document that caller must keep SAB alive during analysis
- Add RAII guard to verify SAB not detached

### Blocker 5: Migration Complexity

**Issue:** 8+ extensions need coordinated refactor.

**Mitigation:**
- Create `hexcore-common` SharedMemoryBuffer abstraction first
- Migrate extensions incrementally (see roadmap)
- Maintain backward compatibility during transition
- Feature flag: `HEXCORE_ZERO_COPY=1`

---

## Implementation Roadmap

### Phase 1: Foundation (hexcore-common)

**Duration:** 2 weeks
**Deliverables:**
- `SharedMemoryBuffer` TypeScript class
- `SharedBufferHeader` C++ struct
- `Napi::ArrayBuffer` utilities
- Unit tests for synchronization primitives

**Key APIs:**
```typescript
class SharedMemoryBuffer {
    constructor(size: number);
    acquireLock(): boolean;
    releaseLock(): void;
    getDataView(): Uint8Array;
    getHeaderView(): Int32Array;
}
```

### Phase 2: Unicorn Extension Refactor

**Duration:** 3 weeks
**Deliverables:**
- Hook callback system using SAB
- Benchmark: 50K → 10M instructions/sec
- Migration guide for other extensions

**Changes:**
- Replace `Buffer` parameters with `SharedArrayBuffer`
- Implement lock-free hook ring buffer
- Add `unicorn.setSharedMemoryBuffer()` API

### Phase 3: Remill/Capstone Refactor

**Duration:** 2 weeks
**Deliverables:**
- `liftInstructionView()` API
- `disassembleBlock()` SAB support
- Integration tests

### Phase 4: Remaining Extensions

**Duration:** 2 weeks
**Deliverables:**
- llvm-mc: assembly with SAB input
- better-sqlite3: blob handling
- souper: candidate buffer optimization
- Documentation updates

---

## Benchmark Targets

### Current Baseline

| Workload | Metric | Current | Target | Speedup |
|----------|--------|---------|--------|---------|
| Unicorn hook latency | avg time/hook | 20 μs | 0.1 μs | 200x |
| Instructions/sec | throughput | 50K | 10M | 200x |
| Remill lift batch | ops/sec | 1K | 5K | 5x |
| Capstone disasm | MB/s | 50 | 100 | 2x |

### Benchmark Methodology

```typescript
// Pseudocode for unicorn benchmark
const iterations = 1_000_000;
const code = Buffer.from([0x90, 0x90, 0x90, 0xC3]); // NOP NOP NOP RET

// Current (copy)
const start = performance.now();
for (let i = 0; i < iterations; i++) {
    uc.hook_add(HOOK_CODE, (uc, addr, size, user_data) => {
        // user_data is copied Buffer
        const data = Buffer.from(user_data);  // COPY
    }, code);
    uc.emu_start(0x1000, 0x1004);
}
const copyTime = performance.now() - start;

// Zero-copy (SAB)
const sab = new SharedArrayBuffer(1024);
const start2 = performance.now();
for (let i = 0; i < iterations; i++) {
    uc.hook_add_sab(HOOK_CODE, (uc, addr, size, sab_offset) => {
        // direct SAB access, no copy
        const data = new Uint8Array(sab, sab_offset, size);  // VIEW, not copy
    }, sab);
    uc.emu_start(0x1000, 0x1004);
}
const zeroCopyTime = performance.now() - start2;

console.log(`Speedup: ${copyTime / zeroCopyTime}x`);
```

### Success Criteria

- **Primary:** 100x speedup for Unicorn hook-heavy workloads
- **Secondary:** <10% regression in any existing benchmark
- **Tertiary:** No increase in memory usage under steady-state

---

## Risks & Decision Points

### High Risk

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| SharedArrayBuffer disabled in enterprise environments | Medium | High | Fallback to copy mode; feature detection |
| Thread safety bugs in native code | Medium | Critical | Extensive testing; AddressSanitizer; code review |
| Electron SAB bugs on specific platforms | Low | High | CI testing on all target platforms |

### Medium Risk

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| API breakage in existing extensions | Medium | Medium | Deprecation cycle; backward compat layer |
| Memory leaks with long-lived SAB | Low | Medium | RAII guards; weakref tracking |
| Performance regression for small data | Medium | Medium | Threshold heuristic (<64 bytes = copy) |

### Decision Points

1. **Go/No-Go for v4.0.0 inclusion**
   - Decision date: End of Phase 1
   - Criteria: PoC achieves >100x speedup, no blocking issues

2. **Default enablement**
   - Decision date: End of Phase 2
   - Options: (a) Opt-in via config (b) Default on with fallback (c) Always on

3. **Legacy API deprecation**
   - Decision date: v4.1.0 planning
   - Options: (a) Keep forever (b) Deprecate in v5.0 (c) Remove in v5.0

---

## Appendix A: Memory Layout Details

### SharedBufferHeader (64 bytes, cache-line aligned)

```c
// C++ definition
struct alignas(64) SharedBufferHeader {
    // Lock/synchronization (4 bytes)
    std::atomic<int32_t> lockFlag;

    // Data metadata (8 bytes)
    uint32_t dataSize;
    int32_t  status;

    // Ordering/debug (16 bytes)
    uint32_t sequenceId;
    uint32_t reserved;
    uint64_t timestamp;

    // Extension-specific (16 bytes)
    uint64_t userData1;
    uint64_t userData2;

    // Padding to 64 bytes
    uint8_t  padding[16];
};
static_assert(sizeof(SharedBufferHeader) == 64, "Header must be 64 bytes");
```

### Region Layout

```
Offset    Content
─────────────────────────────────────────
0x0000    Header (64 bytes)
0x0040    Data payload (configurable)
          - Round-robin ring buffer for hooks
          - Single region for lifting/disasm
```

---

## Appendix B: Related Work

- **V8 SharedArrayBuffer:** https://v8.dev/features/sharedarraybuffer
- **N-API ArrayBuffer:** https://nodejs.org/api/n-api.html#n_api_napi_create_arraybuffer
- **Atomics API:** https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Atomics
- **Electron SAB:** https://www.electronjs.org/docs/latest/tutorial/security#sharedarraybuffer

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-04-11 | HexCore Team | Initial draft for v4.0.0 feasibility study |

---

*This document is part of the HexCore v4.0.0 roadmap. For questions, contact the HexCore architecture team.*
