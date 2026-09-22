#ifndef HFA_PINNED_DOBBY_H
#define HFA_PINNED_DOBBY_H

#include <stdint.h>

#if !defined(__arm64__) && !defined(__aarch64__)
#error HFAMap Dobby instrumentation currently supports arm64 only
#endif

typedef union HFA_DobbyFPReg {
    __int128_t q;
    struct { double d1, d2; } d;
    struct { float f1, f2, f3, f4; } f;
} FPReg;

typedef struct {
    uint64_t dmmpy_0;
    uint64_t sp;
    uint64_t dmmpy_1;
    union {
        uint64_t x[29];
        struct {
            uint64_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11,
                     x12, x13, x14, x15, x16, x17, x18, x19, x20, x21,
                     x22, x23, x24, x25, x26, x27, x28;
        } regs;
    } general;
    uint64_t fp;
    uint64_t lr;
    union { FPReg q[32]; } floating;
} DobbyRegisterContext;

typedef void (*dobby_instrument_callback_t)(void *address, DobbyRegisterContext *ctx);

#ifdef __cplusplus
extern "C" {
#endif
int DobbyHook(void *address, void *fake_func, void **out_origin_func);
int DobbyInstrument(void *address, dobby_instrument_callback_t pre_handler);
int DobbyDestroy(void *address);
const char *DobbyGetVersion(void);
#ifdef __cplusplus
}
#endif

#endif
