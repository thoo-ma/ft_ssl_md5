#pragma once

#include <stdio.h> // for FILE
#include <search.h> // for ENTRY

#define OPTION_P (1 << 0) // 00000001
#define OPTION_Q (1 << 1) // 00000010
#define OPTION_R (1 << 2) // 00000100
#define OPTION_S (1 << 3) // 00001000

#define IS_OPTION_P(options) (options & OPTION_P)
#define IS_OPTION_Q(options) (options & OPTION_Q)
#define IS_OPTION_R(options) (options & OPTION_R)
#define IS_OPTION_S(options) (options & OPTION_S)

#define SET_OPTION_P(options) (options |= OPTION_P)
#define SET_OPTION_Q(options) (options |= OPTION_Q)
#define SET_OPTION_R(options) (options |= OPTION_R)
#define SET_OPTION_S(options) (options |= OPTION_S)

#define UNSET_OPTION_P(options) (options &= ~OPTION_P)
#define UNSET_OPTION_Q(options) (options &= ~OPTION_Q)
#define UNSET_OPTION_R(options) (options &= ~OPTION_R)
#define UNSET_OPTION_S(options) (options &= ~OPTION_S)

/// @brief The size of a block in bytes (64 bytes = 512 bits)
#define BLOCK_SIZE 64

/// @brief The number of 512 bits blocks in a chunk
#define CHUNK_NUMBERS 10

/// @brief The number of 512 bits blocks read at a time
#define CHUNK_SIZE_READ (BLOCK_SIZE * CHUNK_NUMBERS)

/// @brief The total number of 512 bits blocks in a chunk (one extra for padding)
#define CHUNK_SIZE_TOTAL (CHUNK_SIZE_READ + BLOCK_SIZE)

typedef struct {
    ENTRY entry;
    uint8_t options;
    char * filename;
    char * p_message;
    size_t message_size;
    uint32_t hash[8];
    uint8_t words_number; // the number of 32-bit words in the hash.
    uint8_t chunk[CHUNK_SIZE_TOTAL];
    size_t chunk_size;
} ft_ssl_context_t;

typedef char * hash_type_t;
typedef void (*hash_function_t)(ft_ssl_context_t *, FILE * file);

void md5(ft_ssl_context_t *, FILE * file);
void sha256(ft_ssl_context_t *, FILE * file);

extern const hash_type_t hash_types[]; // possible values for ENTRY key
extern const hash_function_t hash_functions[]; // possible values for ENTRY data

// extern const hash_context_t hash_contexts[];

// type
// - context
// - padding
// - update
// - final
