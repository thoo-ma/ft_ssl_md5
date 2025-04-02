#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "ft_ssl.h" // for CHUNK_SIZE_TOTAL

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define F(a, b, c) (((a) & (b)) | ((~a) & (c)))
#define G(a, b, c) (((a) & (c)) | ((b) & (~c)))
#define H(a, b, c) ((a) ^ (b) ^ (c))
#define I(a, b, c) ((b) ^ ((a) | (~c)))

#define FF(a, b, c, d, k, s, i) \
    (a) += F((b), (c), (d)) + (k) + (i); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b);

#define GG(a, b, c, d, k, s, i) \
    (a) += G((b), (c), (d)) + (k) + (i); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b);

#define HH(a, b, c, d, k, s, i) \
    (a) += H((b), (c), (d)) + (k) + (i); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b);

#define II(a, b, c, d, k, s, i) \
    (a) += I((b), (c), (d)) + (k) + (i); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); 

void md5(ft_ssl_context_t * context, FILE * file);