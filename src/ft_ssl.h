#pragma once

#include <search.h> // for ENTRY
#include <stdio.h>  // for FILE

/// @brief Option flags for the ft_ssl command
#define OPTION_P (1 << 0) // Print input (echo mode)
#define OPTION_Q (1 << 1) // Quiet mode
#define OPTION_R (1 << 2) // Reverse format
#define OPTION_S (1 << 3) // String input mode

#define IS_OPTION_P(options) ((options) & OPTION_P)
#define IS_OPTION_Q(options) ((options) & OPTION_Q)
#define IS_OPTION_R(options) ((options) & OPTION_R)
#define IS_OPTION_S(options) ((options) & OPTION_S)

#define SET_OPTION_P(options) ((options) |= OPTION_P)
#define SET_OPTION_Q(options) ((options) |= OPTION_Q)
#define SET_OPTION_R(options) ((options) |= OPTION_R)
#define SET_OPTION_S(options) ((options) |= OPTION_S)

#define UNSET_OPTION_P(options) ((options) &= ~OPTION_P)
#define UNSET_OPTION_Q(options) ((options) &= ~OPTION_Q)
#define UNSET_OPTION_R(options) ((options) &= ~OPTION_R)
#define UNSET_OPTION_S(options) ((options) &= ~OPTION_S)

/// @brief The size of a block in bytes (64 bytes = 512 bits)
#define BLOCK_SIZE 64

/// @brief The number of 512 bits blocks in a chunk
#define CHUNK_NUMBERS 10

/// @brief The number of 512 bits blocks read at a time
#define CHUNK_SIZE_READ (BLOCK_SIZE * CHUNK_NUMBERS)

/// @brief The total number of 512 bits blocks in a chunk (one extra for padding)
#define CHUNK_SIZE_TOTAL (CHUNK_SIZE_READ + BLOCK_SIZE)

/// @brief Context for ft_ssl operations
typedef struct {
    ENTRY entry;                     ///< Hash table entry for the algorithm
    uint32_t hash[8];                ///< Hash result buffer (max 8 words needed for SHA-256)
    uint8_t chunk[CHUNK_SIZE_TOTAL]; ///< Buffer for input data
    char * filename;                 ///< Input filename
    char * p_message;                ///< Input message (when using -s option)
    size_t message_size;             ///< Total message size
    size_t chunk_size;               ///< Current chunk size
    uint8_t options;                 ///< Command line options
} ft_ssl_context_t;

/// @brief Algorithm function pointers structure
typedef struct {
    const char * lower_name;                    ///< Lowercase name (for command line)
    const char * upper_name;                    ///< Uppercase name (for output formatting)
    size_t word_count;                          ///< Number of words in hash output
    void (*f)(ft_ssl_context_t *, FILE * file); ///< Hash function
} ft_ssl_algorithm_t;

void md5(ft_ssl_context_t * context, FILE * file);
void sha256(ft_ssl_context_t * context, FILE * file);
