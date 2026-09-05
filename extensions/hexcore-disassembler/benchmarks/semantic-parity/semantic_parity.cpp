#include <cstdarg>
#include <cstdint>
#include <cstdlib>

#if defined(_MSC_VER)
#define API extern "C" __declspec(dllexport) __declspec(noinline)
#define NORETURN __declspec(noreturn)
#else
#define API extern "C" __attribute__((dllexport, noinline))
#define NORETURN __attribute__((noreturn))
#endif

using callback_t = int (*)(int);
enum class Mode : uint32_t { Read = 1, Write = 2, Execute = 4 };
typedef uint64_t object_id_t;

#pragma pack(push, 1)
struct PackedHeader {
    uint8_t tag;
    uint32_t length;
    uint16_t flags : 3;
    uint16_t kind : 5;
    uint16_t reserved : 8;
};
#pragma pack(pop)

union Overlay { uint64_t whole; uint32_t halves[2]; uint8_t bytes[8]; };
struct NestedRecord { PackedHeader header; Overlay payload; Mode mode; callback_t callback; };
struct BigReturn { uint64_t first; uint64_t second; uint64_t third; };

struct VirtualBase {
    virtual int transform(int value) = 0;
    virtual ~VirtualBase() = default;
};
struct VirtualImpl final : VirtualBase {
    int bias;
    explicit VirtualImpl(int value) : bias(value) {}
    int transform(int value) override { return value + bias; }
};

volatile uint64_t g_counter = 0;
const char g_marker[] = "HEXCORE_SEMANTIC_PARITY";

// HXGT {"function":"cc_cdecl","x86Convention":"cdecl","x64Convention":"win64","parameters":2}
API int __cdecl cc_cdecl(int left, int right) { return left + right; }
// HXGT {"function":"cc_stdcall","x86Convention":"stdcall","x64Convention":"win64","parameters":2}
API int __stdcall cc_stdcall(int left, int right) { return left - right; }
// HXGT {"function":"cc_fastcall","x86Convention":"fastcall","x64Convention":"win64","parameters":2}
API int __fastcall cc_fastcall(int left, int right) { return left ^ right; }
// HXGT {"function":"cc_vectorcall","x86Convention":"vectorcall","x64Convention":"win64","parameters":4}
API int __vectorcall cc_vectorcall(int a, int b, int c, int d) { return a + b + c + d; }

class ThisFixture {
public:
    int base;
    // HXGT_INTERNAL {"symbol":"ThisFixture::method","x86Convention":"thiscall","x64Convention":"win64","parameters":1,"hiddenThis":true}
    __declspec(noinline) int __thiscall method(int value) { return base + value; }
};
// HXGT {"function":"cc_thiscall","x86Convention":"cdecl","x64Convention":"win64","parameters":2,"callsThiscall":true}
API int cc_thiscall(ThisFixture *self, int value) { return self->method(value); }

// HXGT {"function":"cc_variadic","x86Convention":"cdecl","x64Convention":"win64","parameters":1,"variadic":true}
API int __cdecl cc_variadic(int count, ...) {
    va_list args; va_start(args, count); int total = 0;
    for (int i = 0; i < count; ++i) total += va_arg(args, int);
    va_end(args); return total;
}

// HXGT {"function":"cc_sret","x86Convention":"cdecl","x64Convention":"win64","parameters":1,"sret":true}
API BigReturn cc_sret(uint64_t seed) { return { seed, seed + 1, seed + 2 }; }

// HXGT {"function":"cc_noreturn","x86Convention":"cdecl","x64Convention":"win64","parameters":0,"noreturn":true}
API NORETURN void cc_noreturn() { std::abort(); }

static __declspec(noinline) uint64_t chain_leaf(uint64_t value) { return value * 3; }
static __declspec(noinline) uint64_t chain_backward(uint64_t value) { return chain_leaf(value) + 1; }
static __declspec(noinline) void chain_out(uint64_t value, uint64_t *output) { *output = chain_backward(value); }
static __declspec(noinline) uint64_t chain_select(uint64_t left, uint64_t right, bool choose) { return choose ? left : right; }
// HXGT {"function":"type_chain_entry","chainDepth":4,"outParameter":1,"hasSelect":true,"hasSpillReload":true,"hasCastBarrier":true}
API uint64_t type_chain_entry(uint32_t input, bool choose) {
    uint64_t spill = 0; chain_out(static_cast<uint64_t>(input), &spill);
    const uint32_t narrowed = static_cast<uint32_t>(spill);
    return chain_select(spill, narrowed, choose);
}

// HXGT {"function":"record_roundtrip","record":"NestedRecord","fields":[0,1,5,13,17,21]}
API uint64_t record_roundtrip(NestedRecord *record, uint32_t value) {
    record->header.tag = static_cast<uint8_t>(value);
    record->header.length = value;
    record->header.flags = value & 7;
    record->payload.halves[1] = value;
    record->mode = Mode::Write;
    return record->payload.whole + record->header.length;
}

static int callback_plus_one(int value) { return value + 1; }
// HXGT {"function":"xref_callback","indirectCandidates":["callback_plus_one"],"globalRead":true,"globalWrite":true,"stringReference":true}
API int xref_callback(callback_t callback, int value) {
    callback_t selected = callback ? callback : callback_plus_one;
    g_counter += static_cast<uint64_t>(selected(value));
    return static_cast<int>(g_counter + g_marker[0]);
}

static __declspec(noinline) int jt0(unsigned value) { g_counter += 1; return static_cast<int>(value + 11); }
static __declspec(noinline) int jt1(unsigned value) { g_counter += 2; return static_cast<int>(value + 23); }
static __declspec(noinline) int jt2(unsigned value) { g_counter += 3; return static_cast<int>(value + 37); }
static __declspec(noinline) int jt3(unsigned value) { g_counter += 4; return static_cast<int>(value + 41); }
static __declspec(noinline) int jt4(unsigned value) { g_counter += 5; return static_cast<int>(value + 53); }
static __declspec(noinline) int jt5(unsigned value) { g_counter += 6; return static_cast<int>(value + 67); }
static __declspec(noinline) int jt6(unsigned value) { g_counter += 7; return static_cast<int>(value + 79); }
static __declspec(noinline) int jt7(unsigned value) { g_counter += 8; return static_cast<int>(value + 97); }
// HXGT {"function":"xref_jump_table","jumpTableCases":8,"indirectJump":true}
API int xref_jump_table(unsigned value) {
    switch (value & 7u) {
        case 0: return jt0(value); case 1: return jt1(value); case 2: return jt2(value); case 3: return jt3(value);
        case 4: return jt4(value); case 5: return jt5(value); case 6: return jt6(value); default: return jt7(value);
    }
}

// HXGT {"function":"vtable_create","vtable":true,"allocation":true}
API VirtualBase *vtable_create(int bias) { return new VirtualImpl(bias); }
// HXGT {"function":"vtable_call","vtable":true,"indirectCall":true}
API int vtable_call(VirtualBase *object, int value) { return object->transform(value); }
// HXGT {"function":"vtable_destroy","vtable":true,"free":true}
API void vtable_destroy(VirtualBase *object) { delete object; }

// HXGT_RECORD {"name":"PackedHeader","kind":"struct","sourceDefined":true}
// HXGT_RECORD {"name":"Overlay","kind":"union","sourceDefined":true}
// HXGT_RECORD {"name":"NestedRecord","kind":"struct","sourceDefined":true}
