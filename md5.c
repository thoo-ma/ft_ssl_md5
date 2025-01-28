#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define ROTATE_LEFT(x, n) ((x << n) | (x >> (32 - n)))

static uint32_t k[64] = { 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
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
                          0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

static uint32_t r[64] = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                          5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                          4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                          6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };

static uint32_t h0 = 0x67452301;
static uint32_t h1 = 0xEFCDAB89;
static uint32_t h2 = 0x98BADCFE;
static uint32_t h3 = 0x10325476;

// Pads the input message according to the MD5 specification.
static char * md5_padding(char * input)
{
    uint64_t input_len = strlen(input);
    uint64_t output_len = ((input_len + 8) / 64 + 1) * 64 - 8;
    uint8_t *output = (uint8_t*)malloc(output_len + 8);

    if (output == NULL)
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
static void md5_final(uint32_t *h)
{
    for (int i = 0; i < 4; i++) {
        h[i] = ((h[i] & 0xff) << 24) | ((h[i] & 0xff00) << 8) |
               ((h[i] & 0xff0000) >> 8) | ((h[i] & 0xff000000) >> 24);
    }
}

int main(int ac, char ** av) {

    if (ac != 2) {
        printf("Usage: %s <string>\n", av[0]);
        return 1;
    }

    char * input = md5_padding(av[1]);

    if (input == NULL) {
        printf("Error: memory allocation failed\n");
        return 1;
    }

    // process the message in successive 512-bit chunks
    for (uint64_t i = 0; i < strlen(input); i += 64)
    {
        // break chunk into sixteen 32-bit words
        uint32_t * w = (uint32_t*)(input + i);

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;

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

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }

    uint32_t h[4] = { h0, h1, h2, h3 };
    md5_final(h);

    printf("md5(%s) = %08x%08x%08x%08x\n", av[1], h[0], h[1], h[2], h[3]);
    free(input);

    return 0;
}