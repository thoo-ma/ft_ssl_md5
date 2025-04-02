#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ft_ssl.h"
#include "md5.h"
#include "utils.h"

static void md5_init(uint32_t hash[4]) {
    hash[0] = 0x67452301;
    hash[1] = 0xEFCDAB89;
    hash[2] = 0x98BADCFE;
    hash[3] = 0x10325476;
}

static void md5_pad(uint8_t chunk[CHUNK_SIZE_TOTAL], size_t * chunk_size, size_t message_size) {

    // Add the '1' bit
    chunk[*chunk_size] = 0x80;

    // Append '0' bits to the last 512 bits block of the chunk
    size_t block_index = (*chunk_size + 1) / 64;
    size_t zeros = 64 * (block_index + 1) - *chunk_size - 1 - 8;

    memset(chunk + *chunk_size + 1, 0, zeros);

    // Append the original size in bits (little-endian)
    size_t bit_size = message_size * 8;
    memcpy(chunk + *chunk_size + 1 + zeros, &bit_size, 8);

    *chunk_size = 64 * (block_index + 1);
}

/// @brief Reverse the byte order of each 32-bit word in the hash.
static void md5_final(uint32_t hash[4]) {
    hash[0] = ((hash[0] & 0xff) << 24) | ((hash[0] & 0xff00) << 8) |
              ((hash[0] & 0xff0000) >> 8) | ((hash[0] & 0xff000000) >> 24);
    hash[1] = ((hash[1] & 0xff) << 24) | ((hash[1] & 0xff00) << 8) |
              ((hash[1] & 0xff0000) >> 8) | ((hash[1] & 0xff000000) >> 24);
    hash[2] = ((hash[2] & 0xff) << 24) | ((hash[2] & 0xff00) << 8) |
              ((hash[2] & 0xff0000) >> 8) | ((hash[2] & 0xff000000) >> 24);
    hash[3] = ((hash[3] & 0xff) << 24) | ((hash[3] & 0xff00) << 8) |
              ((hash[3] & 0xff0000) >> 8) | ((hash[3] & 0xff000000) >> 24);
}

static void md5_update(uint8_t chunk[CHUNK_SIZE_TOTAL], size_t chunk_size, uint32_t hash[4]) {

    // Initialize the hash values
    uint32_t a0 = hash[0];
    uint32_t b0 = hash[1];
    uint32_t c0 = hash[2];
    uint32_t d0 = hash[3];

    // Process the message in successive 512-bit chunks
    for (size_t i = 0; i < chunk_size; i += 64) {

        // Break chunk into sixteen 32-bit words
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wcast-align"
        uint32_t * w = (uint32_t *)(chunk + i);
        #pragma GCC diagnostic pop

        uint32_t a = a0;
        uint32_t b = b0;
        uint32_t c = c0;
        uint32_t d = d0;

        // Round 1
        FF(a, b, c, d, w[0],  S11, 0xd76aa478);
        FF(d, a, b, c, w[1],  S12, 0xe8c7b756);
        FF(c, d, a, b, w[2],  S13, 0x242070db);
        FF(b, c, d, a, w[3],  S14, 0xc1bdceee);

        FF(a, b, c, d, w[4],  S11, 0xf57c0faf);
        FF(d, a, b, c, w[5],  S12, 0x4787c62a);
        FF(c, d, a, b, w[6],  S13, 0xa8304613);
        FF(b, c, d, a, w[7],  S14, 0xfd469501);

        FF(a, b, c, d, w[8],  S11, 0x698098d8);
        FF(d, a, b, c, w[9],  S12, 0x8b44f7af);
        FF(c, d, a, b, w[10], S13, 0xffff5bb1);
        FF(b, c, d, a, w[11], S14, 0x895cd7be);

        FF(a, b, c, d, w[12], S11, 0x6b901122);
        FF(d, a, b, c, w[13], S12, 0xfd987193);
        FF(c, d, a, b, w[14], S13, 0xa679438e);
        FF(b, c, d, a, w[15], S14, 0x49b40821);

        // Round 2
        GG(a, b, c, d, w[1],  S21, 0xf61e2562);
        GG(d, a, b, c, w[6],  S22, 0xc040b340);
        GG(c, d, a, b, w[11], S23, 0x265e5a51);
        GG(b, c, d, a, w[0],  S24, 0xe9b6c7aa);

        GG(a, b, c, d, w[5],  S21, 0xd62f105d);
        GG(d, a, b, c, w[10], S22, 0x02441453);
        GG(c, d, a, b, w[15], S23, 0xd8a1e681);
        GG(b, c, d, a, w[4],  S24, 0xe7d3fbc8);

        GG(a, b, c, d, w[9],  S21, 0x21e1cde6);
        GG(d, a, b, c, w[14], S22, 0xc33707d6);
        GG(c, d, a, b, w[3],  S23, 0xf4d50d87);
        GG(b, c, d, a, w[8],  S24, 0x455a14ed);

        GG(a, b, c, d, w[13], S21, 0xa9e3e905);
        GG(d, a, b, c, w[2],  S22, 0xfcefa3f8);
        GG(c, d, a, b, w[7],  S23, 0x676f02d9);
        GG(b, c, d, a, w[12], S24, 0x8d2a4c8a);

        // Round 3
        HH(a, b, c, d, w[5],  S31, 0xfffa3942);
        HH(d, a, b, c, w[8],  S32, 0x8771f681);
        HH(c, d, a, b, w[11], S33, 0x6d9d6122);
        HH(b, c, d, a, w[14], S34, 0xfde5380c);

        HH(a, b, c, d, w[1],  S31, 0xa4beea44);
        HH(d, a, b, c, w[4],  S32, 0x4bdecfa9);
        HH(c, d, a, b, w[7],  S33, 0xf6bb4b60);
        HH(b, c, d, a, w[10], S34, 0xbebfbc70);

        HH(a, b, c, d, w[13], S31, 0x289b7ec6);
        HH(d, a, b, c, w[0],  S32, 0xeaa127fa);
        HH(c, d, a, b, w[3],  S33, 0xd4ef3085);
        HH(b, c, d, a, w[6],  S34, 0x04881d05);

        HH(a, b, c, d, w[9],  S31, 0xd9d4d039);
        HH(d, a, b, c, w[12], S32, 0xe6db99e5);
        HH(c, d, a, b, w[15], S33, 0x1fa27cf8);
        HH(b, c, d, a, w[2],  S34, 0xc4ac5665);

        // Round 4
        II(a, b, c, d, w[0],  S41, 0xf4292244);
        II(d, a, b, c, w[7],  S42, 0x432aff97);
        II(c, d, a, b, w[14], S43, 0xab9423a7);
        II(b, c, d, a, w[5],  S44, 0xfc93a039);

        II(a, b, c, d, w[12], S41, 0x655b59c3);
        II(d, a, b, c, w[3],  S42, 0x8f0ccc92);
        II(c, d, a, b, w[10], S43, 0xffeff47d);
        II(b, c, d, a, w[1],  S44, 0x85845dd1);

        II(a, b, c, d, w[8],  S41, 0x6fa87e4f);
        II(d, a, b, c, w[15], S42, 0xfe2ce6e0);
        II(c, d, a, b, w[6],  S43, 0xa3014314);
        II(b, c, d, a, w[13], S44, 0x4e0811a1);

        II(a, b, c, d, w[4],  S41, 0xf7537e82);
        II(d, a, b, c, w[11], S42, 0xbd3af235);
        II(c, d, a, b, w[2],  S43, 0x2ad7d2bb);
        II(b, c, d, a, w[9],  S44, 0xeb86d391);

        a0 += a;
        b0 += b;
        c0 += c;
        d0 += d;
    }

    hash[0] = a0;
    hash[1] = b0;
    hash[2] = c0;
    hash[3] = d0;
}

void md5(ft_ssl_context_t * context, FILE * file) {
    md5_init(context->hash);
    process_input(context, file, md5_pad, md5_update);
    md5_final(context->hash);
    ft_ssl_print(context, file);
}