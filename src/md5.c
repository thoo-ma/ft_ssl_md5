#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "md5.h"

// Pads the input message according to the MD5 specification.
char * md5_padding(char * input)
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

    // append the original length in bits at the end
    memcpy(output + output_len, &(uint64_t){8 * input_len}, 8);

    return (char *)output;
}

// Reverses the byte order of each 32-bit word in the hash.
static uint32_t * md5_final(uint32_t *h)
{
    static uint32_t result[4];
    for (int i = 0; i < 4; i++) {
        result[i] = ((h[i] & 0xff) << 24) | ((h[i] & 0xff00) << 8) |
                    ((h[i] & 0xff0000) >> 8) | ((h[i] & 0xff000000) >> 24);
    }
    return result;
}

uint32_t * md5(char * input) {

    uint32_t a0 = h0;
    uint32_t b0 = h1;
    uint32_t c0 = h2;
    uint32_t d0 = h3;

   // process the message in successive 512-bit chunks
    for (uint64_t i = 0; i < strlen(input); i += 64)
    {
        // break chunk into sixteen 32-bit words
        uint32_t * w = (uint32_t*)(input + i);

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
            b = b + ROTATE_LEFT((a + f + k[j] + w[g]), r[j]);
            a = temp;
        }

        a0 += a;
        b0 += b;
        c0 += c;
        d0 += d;
    }

    // reverse the byte order of each 32-bit word
    uint32_t h[4] = { a0, b0, c0, d0 };
    return md5_final(h);
}