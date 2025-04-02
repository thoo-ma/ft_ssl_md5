#pragma once

#include "ft_ssl.h" // for ft_ssl_context_t

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

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

void md5(ft_ssl_context_t * context, FILE * file);