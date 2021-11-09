
#ifndef _AFL_HASH_H

#define _AFL_HASH_H

/* This is an exerpt of xxhash/XXH3 to prevent colliding with xxhash that is
   in QEMU */

#include <stdio.h>
#include <limits.h>
#include <stdint.h>

uint32_t afl_hash_ip(uint8_t *input, size_t len);
uint32_t AFL_readLE32(const void *memPtr);
uint64_t AFL_readLE64(const void *memPtr);
uint64_t AFL_rrmxmx(uint64_t h64, uint64_t len);

const uint8_t AFL_kSecret[] = {

    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c,
    0xf7, 0x21, 0xad, 0x1c, 0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb,
    0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f, 0xcb, 0x79, 0xe6, 0x4e,
    0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6,
    0x81, 0x3a, 0x26, 0x4c, 0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb,
    0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3, 0x71, 0x64, 0x48, 0x97,
    0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7,
    0xc7, 0x0b, 0x4f, 0x1d, 0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31,
    0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64, 0xea, 0xc5, 0xac, 0x83,
    0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26,
    0x29, 0xd4, 0x68, 0x9e, 0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc,
    0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce, 0x45, 0xcb, 0x3a, 0x8f,
    0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,

};

#define AFL_rotl64(x, r) (((x) << (r)) | ((x) >> (64 - (r))))

inline uint32_t AFL_readLE32(const void *memPtr) {

  const uint8_t *bytePtr = (const uint8_t *)memPtr;
  return bytePtr[0] | ((uint32_t)bytePtr[1] << 8) | ((uint32_t)bytePtr[2] << 16) |
         ((uint32_t)bytePtr[3] << 24);

}

inline uint64_t AFL_readLE64(const void *memPtr) {

  const uint8_t *bytePtr = (const uint8_t *)memPtr;
  return bytePtr[0] | ((uint64_t)bytePtr[1] << 8) | ((uint64_t)bytePtr[2] << 16) |
         ((uint64_t)bytePtr[3] << 24) | ((uint64_t)bytePtr[4] << 32) |
         ((uint64_t)bytePtr[5] << 40) | ((uint64_t)bytePtr[6] << 48) |
         ((uint64_t)bytePtr[7] << 56);

}

inline uint64_t AFL_rrmxmx(uint64_t h64, uint64_t len) {

  /* this mix is inspired by Pelle Evensen's rrmxmx */
  h64 ^= AFL_rotl64(h64, 49) ^ AFL_rotl64(h64, 24);
  h64 *= 0x9FB21C651E98DF25ULL;
  h64 ^= (h64 >> 35) + len;
  h64 *= 0x9FB21C651E98DF25ULL;
  return h64 ^ (h64 >> 28);

}

inline uint32_t afl_hash_ip(uint8_t *input, size_t len) {

  const uint8_t *secret = AFL_kSecret;

    uint32_t const input1 = AFL_readLE32(input);
    uint32_t const input2 = AFL_readLE32(input + len - 4);
    uint64_t const bitflip =
        (AFL_readLE64(secret + 8) ^ AFL_readLE64(secret + 16));
    uint64_t const input64 = input2 + (((uint64_t)input1) << 32);
    uint64_t const keyed = input64 ^ bitflip;
    return AFL_rrmxmx(keyed, len);

}

#endif
