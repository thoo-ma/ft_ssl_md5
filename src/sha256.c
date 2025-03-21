#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef DEBUG
#include <stdio.h>
#include <unistd.h>
#endif

#include "ft_ssl.h"
#include "sha256.h"

void sha256_init(uint32_t hash[8]) {
    hash[0] = sha256_context.h0;
    hash[1] = sha256_context.h1;
    hash[2] = sha256_context.h2;
    hash[3] = sha256_context.h3;
    hash[4] = sha256_context.h4;
    hash[5] = sha256_context.h5;
    hash[6] = sha256_context.h6;
    hash[7] = sha256_context.h7;
}

void sha256_padding(uint8_t chunk[CHUNK_SIZE_TOTAL], size_t * chunk_size, size_t message_size) {
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
    for (size_t i = 0; i < 8; i++)
        chunk[*chunk_size + 1 + zeros + i] = (bit_size >> (56 - 8 * i)) & 0xFF;

    *chunk_size = 64 * (block_index + 1);

    #ifdef DEBUG
    fprintf(stderr, "__ chunk_size: %lu\n", *chunk_size);
    #endif
}

void sha256_update(uint8_t chunk[CHUNK_SIZE_TOTAL], size_t chunk_size, uint32_t hash[8]) {

    // Load the state
    uint32_t a0 = hash[0];
    uint32_t b0 = hash[1];
    uint32_t c0 = hash[2];
    uint32_t d0 = hash[3];
    uint32_t e0 = hash[4];
    uint32_t f0 = hash[5];
    uint32_t g0 = hash[6];
    uint32_t h0 = hash[7];

    // process the message in successive 512-bit chunks
    for (size_t i = 0; i < chunk_size; i += 64) {

        // prepare the message schedule
        uint32_t w[64] = {0};

        for (uint8_t j = 0; j < 16; j++)
            w[j] = (uint32_t)(chunk[i + j * 4] << 24) | (uint32_t)(chunk[i + j * 4 + 1] << 16) | (uint32_t)(chunk[i + j * 4 + 2] << 8) | (uint32_t)(chunk[i + j * 4 + 3]);

        for (uint8_t j = 16; j < 64; j++)
            w[j] = SSIG1(w[j - 2]) + w[j - 7] + SSIG0(w[j - 15]) + w[j - 16];

        // initialize the working variables
        uint32_t a = a0;
        uint32_t b = b0;
        uint32_t c = c0;
        uint32_t d = d0;
        uint32_t e = e0;
        uint32_t f = f0;
        uint32_t g = g0;
        uint32_t h = h0;

        // main loop
        for (uint8_t j = 0; j < 64; j++) {

            uint32_t t1 = h + BSIG1(e) + CH(e, f, g) + sha256_context.k[j] + w[j];
            uint32_t t2 = BSIG0(a) + MAJ(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        // compute the intermediate hash value
        a0 += a;
        b0 += b;
        c0 += c;
        d0 += d;
        e0 += e;
        f0 += f;
        g0 += g;
        h0 += h;
    }

    // Update the state
    hash[0] = a0;
    hash[1] = b0;
    hash[2] = c0;
    hash[3] = d0;
    hash[4] = e0;
    hash[5] = f0;
    hash[6] = g0;
    hash[7] = h0;
}