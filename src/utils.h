#pragma once

#include "ft_ssl.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

/// @brief Print hash result with appropriate formatting based on context options
void ft_ssl_print(ft_ssl_context_t * context, FILE * file);

/// @brief Process input data and compute hash
void process_input(
    ft_ssl_context_t * context,
    FILE * file,
    void (*padding)(uint8_t *, size_t *, size_t),
    void (*update)(uint8_t *, size_t, uint32_t *)
);