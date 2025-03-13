#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef DEBUG
#include <stdio.h>
#include <unistd.h>
#endif

#include "ft_ssl.h"
#include "md5.h"

void md5_init(uint32_t hash[4]) {
    hash[0] = md5_context.h0;
    hash[1] = md5_context.h1;
    hash[2] = md5_context.h2;
    hash[3] = md5_context.h3;
}

void md5_padding(uint8_t chunk[CHUNK_SIZE_TOTAL], size_t * chunk_size, size_t message_size) {
    #ifdef DEBUG
    fprintf(stderr, "GO pad\n");
    #endif

    // end the '1' bit
    chunk[*chunk_size] = 0x80;

    #ifdef DEBUG
    fprintf(stderr, "chunk_size: %lu\n", *chunk_size);
    fprintf(stderr, "message_size: %lu\n", message_size);
    #endif

    // append '0' bits to the last 512 bits block of the chunk
    size_t block_index = (*chunk_size + 1) / 64;
    size_t zeros = 64 * (block_index + 1) - *chunk_size - 1 - 8;

    #ifdef DEBUG
    fprintf(stderr, "block_index: %lu\n", block_index);
    fprintf(stderr, "zeros: %lu\n", zeros);
    #endif

    memset(chunk + *chunk_size + 1, 0, zeros);

    #ifdef DEBUG
    write(2, chunk, *chunk_size);
    write(2, "\n", 1);
    #endif

    // append the original size in bits
    size_t bit_size = message_size * 8;
    memcpy(chunk + *chunk_size + 1 + zeros, &bit_size, 8);

    *chunk_size = 64 * (block_index + 1);

    #ifdef DEBUG
    fprintf(stderr, "__ chunk_size: %lu\n", *chunk_size);
    #endif
}

/// @brief Reverse the byte order of each 32-bit word in the hash.
void md5_final(uint32_t hash[4]) {
    hash[0] = ((hash[0] & 0xff) << 24) | ((hash[0] & 0xff00) << 8) |
              ((hash[0] & 0xff0000) >> 8) | ((hash[0] & 0xff000000) >> 24);
    hash[1] = ((hash[1] & 0xff) << 24) | ((hash[1] & 0xff00) << 8) |
              ((hash[1] & 0xff0000) >> 8) | ((hash[1] & 0xff000000) >> 24);
    hash[2] = ((hash[2] & 0xff) << 24) | ((hash[2] & 0xff00) << 8) |
              ((hash[2] & 0xff0000) >> 8) | ((hash[2] & 0xff000000) >> 24);
    hash[3] = ((hash[3] & 0xff) << 24) | ((hash[3] & 0xff00) << 8) |
              ((hash[3] & 0xff0000) >> 8) | ((hash[3] & 0xff000000) >> 24);
}

void md5_update(uint8_t chunk[CHUNK_SIZE_TOTAL], size_t chunk_size, uint32_t hash[4]) {

    // initialize the hash values
    uint32_t a0 = hash[0];
    uint32_t b0 = hash[1];
    uint32_t c0 = hash[2];
    uint32_t d0 = hash[3];

    // process the message in successive 512-bit chunks
    for (size_t i = 0; i < chunk_size; i += 64) {
        // break chunk into sixteen 32-bit words
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wcast-align"
        uint32_t * w = (uint32_t *)(chunk + i);
        #pragma GCC diagnostic pop

        uint32_t a = a0;
        uint32_t b = b0;
        uint32_t c = c0;
        uint32_t d = d0;

        // loop over each 32-bit word
        for (uint8_t j = 0; j < 64; j++) {

            uint32_t f, g;

            if (j < 16) {
                // round 1
                f = (b & c) | ((~b) & d);
                g = j;
            } else if (j < 32) {
                // round 2
                f = (d & b) | ((~d) & c);
                g = (5 * j + 1) % 16;
            } else if (j < 48) {
                // round 3
                f = b ^ c ^ d;
                g = (3 * j + 5) % 16;
            } else {
                // round 4
                f = c ^ (b | (~d));
                g = (7 * j) % 16;
            }

            uint32_t temp = d;
            d = c;
            c = b;
            b = b + ROTATE_LEFT((a + f + md5_context.k[j] + w[g]), md5_context.r[j]);
            a = temp;
        }

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