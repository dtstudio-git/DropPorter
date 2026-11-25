#pragma once
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define BYTE_ORDER 1234
#define PACK_STRUCT_BEGIN __pragma(pack(push,1))
#define PACK_STRUCT_END __pragma(pack(pop))
#define PACK_STRUCT_STRUCT
#define LWIP_PLATFORM_DIAG(x) do { printf x; } while (0)
#define LWIP_PLATFORM_ASSERT(x) do { fprintf(stderr,"lwIP assertion: %s\n",x); abort(); } while (0)
#ifdef __cplusplus
extern "C" {
#endif
uint32_t awdl_lwip_random(void);
#ifdef __cplusplus
}
#endif
#define LWIP_RAND() awdl_lwip_random()
