#include "utils.h"
#include <stdio.h>

static void print_hash(ft_ssl_context_t * context) {
    for (size_t i = 0; i < ((ft_ssl_algorithm_t *)context->entry.data)->word_count; i++)
        printf("%08x", context->hash[i]);
}

void ft_ssl_print(ft_ssl_context_t * context, FILE * file) {

    if (file == stdin && IS_OPTION_P(context->options)) {
        print_hash(context);
        printf("\n");
    } else if (IS_OPTION_Q(context->options)) {
        print_hash(context);
        printf("\n");
    } else if (IS_OPTION_R(context->options)) {
        print_hash(context);
        context->p_message
        ? printf(" \"%s\"\n", context->p_message)
        : printf(" *%s\n", context->filename ? context->filename : "stdin");
    } else {
        if (context->filename) {
            printf("%s(%s)= ", ((ft_ssl_algorithm_t *)context->entry.data)->upper_name, context->filename);
        } else if (IS_OPTION_S(context->options) && file != stdin) {
            printf("%s(\"%s\")= ", ((ft_ssl_algorithm_t *)context->entry.data)->upper_name, context->p_message);
        } else if (IS_OPTION_P(context->options) && context->p_message) {
            printf("(\"%s\")= ", context->p_message);
        } else {
            printf("%s(stdin)= ", ((ft_ssl_algorithm_t *)context->entry.data)->upper_name);
        }
        print_hash(context);
        printf("\n");
    }
}

void process_input(ft_ssl_context_t * context, FILE * file, void (*pad)(uint8_t *, size_t *, size_t), void (*update)(uint8_t *, size_t, uint32_t *)) {

    if (file == stdin && IS_OPTION_P(context->options) && !IS_OPTION_Q(context->options))
        write(1, "(\"", 2);

    size_t read_bytes = 0;
    bool padding_done = false;

    // Process all input in chunks
    while ((read_bytes = fread(context->chunk, 1, CHUNK_SIZE_READ, file)) > 0) {
        context->chunk_size = read_bytes;
        context->message_size += read_bytes;
        
        if (file == stdin && IS_OPTION_P(context->options))
            write(1, context->chunk, read_bytes);
        
        // Apply padding if this is the final chunk
        if (read_bytes < CHUNK_SIZE_READ) {
            pad(context->chunk, &context->chunk_size, context->message_size);
            padding_done = true;
            update(context->chunk, context->chunk_size, context->hash);
        } else {
            // Process full chunks without padding
            update(context->chunk, read_bytes, context->hash);
            
            // Check if we've reached EOF
            int c = fgetc(file);
            if (c == EOF) {
                // Reset chunk for padding
                context->chunk_size = 0;
                pad(context->chunk, &context->chunk_size, context->message_size);
                padding_done = true;
                update(context->chunk, context->chunk_size, context->hash);
            } else {
                // Put the character back
                ungetc(c, file);
            }
        }
    }

    // Handle empty files or final padding for files where we didn't hit EOF within the read
    if (!padding_done) {
        context->chunk_size = 0;
        pad(context->chunk, &context->chunk_size, context->message_size);
        update(context->chunk, context->chunk_size, context->hash);
    }

    if (file == stdin && IS_OPTION_P(context->options) && !IS_OPTION_Q(context->options))
        write(1, "\")= ", 4);
}