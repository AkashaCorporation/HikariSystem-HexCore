#include <stdint.h>
#include <stddef.h>

typedef int (*transform_cb)(int value, void *context);
enum operation_mode { MODE_READ = 1, MODE_WRITE = 2, MODE_EXECUTE = 4 };

struct packed_header {
    uint8_t tag;
    uint32_t length;
    uint16_t flags : 3;
    uint16_t kind : 5;
    uint16_t reserved : 8;
} __attribute__((packed));

union overlay_value { uint64_t whole; uint32_t halves[2]; uint8_t bytes[8]; };
struct semantic_context {
    struct packed_header header;
    union overlay_value payload;
    enum operation_mode mode;
    transform_cb callback;
    void *callback_context;
};

__attribute__((visibility("default"), noinline))
uint64_t semantic_update(struct semantic_context *context, uint32_t value) {
    context->header.tag = (uint8_t)value;
    context->header.length = value;
    context->header.flags = value & 7u;
    context->payload.halves[1] = value;
    context->mode = MODE_WRITE;
    return context->payload.whole + context->header.length;
}

__attribute__((visibility("default"), noinline))
int semantic_callback(struct semantic_context *context, int value) {
    if (!context || !context->callback) return -1;
    return context->callback(value, context->callback_context);
}

__attribute__((visibility("default"), noinline))
int semantic_switch(unsigned value) {
    switch (value & 7u) {
        case 0: return 11; case 1: return 23; case 2: return 37; case 3: return 41;
        case 4: return 53; case 5: return 67; case 6: return 79; default: return 97;
    }
}
