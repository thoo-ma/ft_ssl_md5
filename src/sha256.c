#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ft_ssl.h"
#include "sha256.h"
#include "utils.h"

static void sha256_init(uint32_t hash[8]) {
    hash[0] = 0x6a09e667;
    hash[1] = 0xbb67ae85;
    hash[2] = 0x3c6ef372;
    hash[3] = 0xa54ff53a;
    hash[4] = 0x510e527f;
    hash[5] = 0x9b05688c;
    hash[6] = 0x1f83d9ab;
    hash[7] = 0x5be0cd19;
}

static void sha256_pad(uint8_t chunk[CHUNK_SIZE_TOTAL], size_t * chunk_size, size_t message_size) {

    // Append the bit '1' to the message
    chunk[*chunk_size] = 0x80;
    (*chunk_size)++;

    // Calculate padding zeros
    // We need to pad until the total length is congruent to 56 (mod 64)
    // which leaves 8 bytes (64 bits) for the original length.
    size_t current_mod_64 = *chunk_size % 64;
    size_t zeros_to_add;

    if (current_mod_64 <= 56) {
        // Enough space in the current block for the length
        zeros_to_add = 56 - current_mod_64;
    } else {
        // Not enough space, need to pad to the end of this block,
        // and then add 56 zeros in the next block.
        zeros_to_add = (64 - current_mod_64) + 56;
    }

    // Add the zero padding
    memset(chunk + *chunk_size, 0, zeros_to_add);
    *chunk_size += zeros_to_add;

    // Append the original message size in bits (big-endian)
    uint64_t bit_size = message_size * 8;
    for (size_t i = 0; i < 8; i++)
        chunk[*chunk_size + i] = (uint8_t)(bit_size >> (56 - 8 * i));
    *chunk_size += 8;

    // *chunk_size is now the total size of the padded message, a multiple of 64.
}

static void sha256_update(uint8_t chunk[CHUNK_SIZE_TOTAL], size_t chunk_size, uint32_t hash[8]) {

    // Load the state
    uint32_t a0 = hash[0];
    uint32_t b0 = hash[1];
    uint32_t c0 = hash[2];
    uint32_t d0 = hash[3];
    uint32_t e0 = hash[4];
    uint32_t f0 = hash[5];
    uint32_t g0 = hash[6];
    uint32_t h0 = hash[7];

    // Process each 512-bit chunk
    for (size_t i = 0; i < chunk_size; i += 64) {
        uint32_t w[64] = {0};

        // Convert bytes to words (big-endian)
        for (uint8_t j = 0; j < 16; j++) {
            const size_t offset = i + j * 4;
            w[j] = ((uint32_t)chunk[offset] << 24) |
                   ((uint32_t)chunk[offset + 1] << 16) |
                   ((uint32_t)chunk[offset + 2] << 8) |
                   ((uint32_t)chunk[offset + 3]);
        }

        // Extend the first 16 words to the remaining 48 words
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

        // Compression function main loop
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

        // Compute the intermediate hash value
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

void sha256(ft_ssl_context_t * context, FILE * file) {
    sha256_init(context->hash);
    process_input(context, file, sha256_pad, sha256_update);
    ft_ssl_print(context, file);
}