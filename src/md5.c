#include <string.h>
#include <stdint.h>
#include <stdlib.h>
// #include <stdio.h> // DEBUG
// #include <unistd.h> // DEBUG

#include "md5.h"
#include "ft_ssl.h"

void md5_padding(uint8_t chunk[CHUNK_SIZE_TOTAL], size_t * chunk_size, size_t message_size)
{
    // DEBUG
    // fprintf(stderr, "GO pad\n");

    // end the '1' bit
    chunk[*chunk_size] = 0x80;

    // DEBUG
    // fprintf(stderr, "chunk_size: %lu\n", *chunk_size);
    // fprintf(stderr, "message_size: %lu\n", message_size);

    // append '0' bits to the last 512 bits block of the chunk
    size_t block_index = (*chunk_size + 1) / 64;
    size_t zeros = 64 * (block_index + 1) - *chunk_size - 1 - 8;

    // DEBUG
    // fprintf(stderr, "block_index: %lu\n", block_index);
    // fprintf(stderr, "zeros: %lu\n", zeros);

    memset(chunk + *chunk_size + 1, 0, zeros);

    // DEBUG
    // write(2, chunk, *chunk_size);
    // write(2, "\n", 1);

    // append the original size in bits
    size_t bit_size = message_size * 8;
    memcpy(chunk + *chunk_size + 1 + zeros, &bit_size, 8);

    *chunk_size = 64 * (block_index + 1);

    // DEBUG
    // fprintf(stderr, "__ chunk_size: %lu\n", *chunk_size);
}

// Reverses the byte order of each 32-bit word in the hash.
void md5_final(uint32_t hash[4])
{
    hash[0] = ((hash[0] & 0xff) << 24) | ((hash[0] & 0xff00) << 8) |
              ((hash[0] & 0xff0000) >> 8) | ((hash[0] & 0xff000000) >> 24);
    hash[1] = ((hash[1] & 0xff) << 24) | ((hash[1] & 0xff00) << 8) |
              ((hash[1] & 0xff0000) >> 8) | ((hash[1] & 0xff000000) >> 24);
    hash[2] = ((hash[2] & 0xff) << 24) | ((hash[2] & 0xff00) << 8) |
              ((hash[2] & 0xff0000) >> 8) | ((hash[2] & 0xff000000) >> 24);
    hash[3] = ((hash[3] & 0xff) << 24) | ((hash[3] & 0xff00) << 8) |
              ((hash[3] & 0xff0000) >> 8) | ((hash[3] & 0xff000000) >> 24);
}

void md5_update(uint8_t chunk[CHUNK_SIZE_TOTAL], size_t size, uint32_t hash[4]) {

    // initialize the hash values
    uint32_t a0 = hash[0];
    uint32_t b0 = hash[1];
    uint32_t c0 = hash[2];
    uint32_t d0 = hash[3];

    // process the message in successive 512-bit chunks
    for (size_t i = 0; i < size; i += 64)
    {
        // break chunk into sixteen 32-bit words
        uint32_t * w = (uint32_t*)(chunk + i);

        uint32_t a = a0;
        uint32_t b = b0;
        uint32_t c = c0;
        uint32_t d = d0;

        // loop over each 32-bit word
        for (uint8_t j = 0; j < 64; j++) {

            uint32_t f, g;

            // round 1
            if (j < 16) {
                f = (b & c) | ((~b) & d);
                g = j;
            // round 2
            } else if (j < 32) {
                f = (d & b) | ((~d) & c);
                g = (5 * j + 1) % 16;
            // round 3
            } else if (j < 48) {
                f = b ^ c ^ d;
                g = (3 * j + 5) % 16;
            // round 4
            } else {
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