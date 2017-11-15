#ifndef HSR_H
#define HSR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void hsr_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
