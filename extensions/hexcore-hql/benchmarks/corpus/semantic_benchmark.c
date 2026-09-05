#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdlib.h>

#if defined(_MSC_VER)
#define BENCH_API __declspec(dllexport) __declspec(noinline)
#else
#define BENCH_API __attribute__((dllexport, noinline))
#endif

typedef struct BenchObject {
    volatile LONG refcount;
    uint8_t *buffer;
    size_t length;
} BenchObject;

BENCH_API uint32_t bench_fnv1_32(const uint8_t *data, size_t length) {
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < length; ++i) {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}

BENCH_API uint64_t bench_fnv1_64(const uint8_t *data, size_t length) {
    uint64_t hash = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < length; ++i) {
        hash ^= data[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

BENCH_API uint32_t bench_crc32_step(uint32_t crc, uint8_t value) {
    crc ^= value;
    for (unsigned bit = 0; bit < 8; ++bit) {
        crc = (crc >> 1) ^ ((0u - (crc & 1u)) & UINT32_C(0xEDB88320));
    }
    return crc;
}

BENCH_API void bench_xor_buffer(uint8_t *data, size_t length, uint8_t key) {
    for (size_t i = 0; i < length; ++i) data[i] ^= key;
}

BENCH_API uint32_t bench_multiply_xor(uint32_t value, uint32_t rounds) {
    for (uint32_t i = 0; i < rounds; ++i) {
        value ^= value >> 13;
        value *= UINT32_C(0x85EBCA6B);
    }
    return value;
}

BENCH_API int bench_guarded_loop(int enabled, const int *values, size_t count) {
    int total = 0;
    if (enabled) {
        size_t i = 0;
        do {
            total += values[i++];
        } while (i < count);
    }
    return total;
}

BENCH_API LONGLONG bench_timing_probe(void) {
    LARGE_INTEGER before = {0};
    LARGE_INTEGER after = {0};
    QueryPerformanceCounter(&before);
    for (volatile unsigned i = 0; i < 32; ++i) { }
    QueryPerformanceCounter(&after);
    return after.QuadPart - before.QuadPart;
}

BENCH_API LSTATUS bench_vm_registry_probe(HKEY key) {
    static const wchar_t value_name[] = L"VEN_VMWARE";
    DWORD value = 0;
    DWORD size = sizeof(value);
    return RegQueryValueExW(key, value_name, NULL, NULL, (BYTE *)&value, &size);
}

BENCH_API NTSTATUS bench_peb_query_probe(HANDLE process, PVOID output, ULONG size) {
    return NtQueryInformationProcess(process, ProcessBasicInformation, output, size, NULL);
}

BENCH_API void bench_refcount_release(BenchObject *object) {
    if (InterlockedDecrement(&object->refcount) == 0) free(object->buffer);
}

BENCH_API void bench_refcount_binary(BenchObject *object) {
    object->refcount -= 1;
    if (object->refcount == 0) free(object->buffer);
}

BENCH_API int bench_plain_add(int left, int right) { return left + right; }

BENCH_API uint32_t bench_plain_rotate(uint32_t value) {
    return (value << 7) | (value >> 25);
}

BENCH_API size_t bench_plain_copy(uint8_t *output, const uint8_t *input, size_t count) {
    size_t copied = 0;
    while (copied < count) {
        output[copied] = input[copied];
        ++copied;
    }
    return copied;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
