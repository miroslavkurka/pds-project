#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

// Constants are the integer part of the sines of integers (in radians) * 2^32.
const uint32_t k[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

// Functions for MD5 rounds
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

// MD5 Transform Function
void md5_transform(uint32_t *state, const uint8_t *block) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], i;
    uint32_t m[16];

    // Convert the input block to 32-bit words
    for (i = 0; i < 16; ++i) {
        m[i] = (uint32_t)block[i * 4] | (uint32_t)block[i * 4 + 1] << 8 |
               (uint32_t)block[i * 4 + 2] << 16 | (uint32_t)block[i * 4 + 3] << 24;
    }

    // Round 1
    for (i = 0; i < 16; ++i) {
        uint32_t f = F(b, c, d);
        uint32_t g = i;
        uint32_t tmp = d;
        d = c;
        c = b;
        b = b + LEFTROTATE((a + f + k[i] + m[g]), 7);
        a = tmp;
    }

    // Round 2
    for (i = 0; i < 16; ++i) {
        uint32_t f = G(b, c, d);
        uint32_t g = (5 * i + 1) % 16;
        uint32_t tmp = d;
        d = c;
        c = b;
        b = b + LEFTROTATE((a + f + k[i + 16] + m[g]), 12);
        a = tmp;
    }

    // Round 3
    for (i = 0; i < 16; ++i) {
        uint32_t f = H(b, c, d);
        uint32_t g = (3 * i + 5) % 16;
        uint32_t tmp = d;
        d = c;
        c = b;
        b = b + LEFTROTATE((a + f + k[i + 32] + m[g]), 17);
        a = tmp;
    }

    // Round 4
    for (i = 0; i < 16; ++i) {
        uint32_t f = I(b, c, d);
        uint32_t g = (7 * i) % 16;
        uint32_t tmp = d;
        d = c;
        c = b;
        b = b + LEFTROTATE((a + f + k[i + 48] + m[g]), 22);
        a = tmp;
    }

    // Update the state
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

// MD5 padding
void md5_pad(uint8_t *initial_msg, uint64_t initial_len) {
    // Append padding
    initial_msg[initial_len++] = 0x80; // Append a single '1' bit
    while (initial_len % 64 != 56) {
        initial_msg[initial_len++] = 0; // Padding with zeros
    }

    // Append length in bits
    uint64_t bit_len = initial_len * 8;
    for (int i = 0; i < 8; ++i) {
        initial_msg[initial_len++] = (uint8_t)(bit_len >> (i * 8));
    }
}

// MD5 hashing function
void md5_hash(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {
    // Initialize variables
    uint32_t state[4] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};
    uint64_t len_in_bits = initial_len * 8;

    // Process the message in blocks
    for (size_t offset = 0; offset < initial_len; offset += 64) {
        // Perform MD5 transformation for each block
        md5_transform(state, &initial_msg[offset]);
    }

    // Pad the message and perform final transformation
    uint8_t padded_msg[128];
    memset(padded_msg, 0, 128);
    memcpy(padded_msg, initial_msg, initial_len);
    padded_msg[initial_len] = 0x80; // Append a single '1' bit
    *((uint64_t*)(padded_msg + 120)) = len_in_bits; // Append length in bits

    md5_transform(state, padded_msg);

    // Copy the state to the digest
    for (int i = 0; i < 4; ++i) {
        digest[i * 4] = (uint8_t)(state[i]);
        digest[i * 4 + 1] = (uint8_t)(state[i] >> 8);
        digest[i * 4 + 2] = (uint8_t)(state[i] >> 16);
        digest[i * 4 + 3] = (uint8_t)(state[i] >> 24);
    }
}