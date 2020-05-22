#ifndef _HELPERS_H
#define _HELPERS_H

/* eBPF requires all functions to be inlined */
#define INTERNAL static __attribute__((always_inline))

/* Log only in debug. */
#ifndef NDEBUG
#define LOG(fmt, ...) bpf_printk(fmt "\n", ##__VA_ARGS__)
#else
#define LOG(fmt, ...)
#endif

/* eBPF lacks these functions, but LLVM provides builtins */
#ifndef memset
#define memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
#define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
#define memmove(dest, src, n)  __builtin_memmove((dest), (src), (n))
#endif

#endif // _HELPERS_H