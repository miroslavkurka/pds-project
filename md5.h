#ifndef MD5_H
#define MD5_H

#include <stdint.h>

void md5_transform(uint32_t *state, const uint8_t *block);
void md5_pad(uint8_t *initial_msg, uint64_t initial_len);
__host__ __device__ md5_hash(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest);

#endif /* MD5_H */
