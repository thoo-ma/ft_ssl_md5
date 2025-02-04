#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "sha256.h"

// Pads the input message according to the SHA256MD5 specification.
uint8_t * sha256_padding(char * input)
{
    uint64_t input_len = strlen(input);
    uint64_t output_len = ((input_len + 8) / 64 + 1) * 64 - 8;
    uint8_t *output = (uint8_t*)malloc(output_len + 8);

    if (!output)
        return NULL;

    // append the message
    memcpy(output, input, input_len);

    // append the '1' bit
    output[input_len] = 0x80;

    // append '0' bits
    memset(output + input_len + 1, 0, output_len - input_len - 1);

    // append the original length in bits at the end in big-endian order
    uint64_t bit_len = 8 * input_len;
    for (int i = 0; i < 8; i++)
        output[(int)output_len + i] = (bit_len >> (56 - 8 * i)) & 0xFF;

    return output;
}

uint32_t * sha256(uint8_t * input) {

    // initialize the hash values
    uint32_t a0 = sha256_context.h0;
    uint32_t b0 = sha256_context.h1;
    uint32_t c0 = sha256_context.h2;
    uint32_t d0 = sha256_context.h3;
    uint32_t e0 = sha256_context.h4;
    uint32_t f0 = sha256_context.h5;
    uint32_t g0 = sha256_context.h6;
    uint32_t h0 = sha256_context.h7;

    // process the message in successive 512-bit chunks
    for (uint64_t i = 0; i < strlen((char *)input); i += 64) {

        // 1. prepare the message schedule
        uint32_t w[64] = {0};

        for (uint8_t j = 0; j < 16; j++)
            w[j] = (uint32_t)(input[i + j * 4] << 24) | (uint32_t)(input[i + j * 4 + 1] << 16) | (uint32_t)(input[i + j * 4 + 2] << 8) | (uint32_t)(input[i + j * 4 + 3]);

        for (uint8_t j = 16; j < 64; j++)
            w[j] = SSIG1(w[j - 2]) + w[j - 7] + SSIG0(w[j - 15]) + w[j - 16];

        // 2. initialize the working variables
        uint32_t a = a0;
        uint32_t b = b0;
        uint32_t c = c0;
        uint32_t d = d0;
        uint32_t e = e0;
        uint32_t f = f0;
        uint32_t g = g0;
        uint32_t h = h0;

        // 3. main loop
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

        // 4. compute the intermediate hash value
        a0 += a;
        b0 += b;
        c0 += c;
        d0 += d;
        e0 += e;
        f0 += f;
        g0 += g;
        h0 += h;
    }

    return ((uint32_t[]){a0, b0, c0, d0, e0, f0, g0, h0});
}