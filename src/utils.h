#pragma once

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include "ft_ssl.h"

/// @brief Print hash result with appropriate formatting based on context options
void ft_ssl_print(ft_ssl_context_t * context, FILE * file); 

/// @brief Process input data and compute hash
/// @param context The ft_ssl context
/// @param file The input file
/// @param padding Function pointer to the padding algorithm
/// @param update Function pointer to the hash update algorithm
void process_input(
    ft_ssl_context_t * context, 
    FILE * file, 
    void (*padding)(uint8_t *, size_t *, size_t), 
    void (*update)(uint8_t *, size_t, uint32_t *)
);