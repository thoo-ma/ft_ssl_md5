#include "utils.h"
#include <stdio.h>

static void print_hash(ft_ssl_context_t * context) {
    for (size_t i = 0; i < ((ft_ssl_algorithm_t *)context->entry.data)->word_count; i++)
        printf("%08x", context->hash[i]);
}

void ft_ssl_print(ft_ssl_context_t * context, FILE * file) {

    // When reading from stdin, flag -p disable flags -q and -r
    if (file == stdin && IS_OPTION_P(context->options)) {
        print_hash(context);
        printf("\n");
        return;
    }

    if (IS_OPTION_Q(context->options)) {
        print_hash(context);
        printf("\n");
        return;
    }

    if (IS_OPTION_R(context->options)) {
        print_hash(context);
        if (context->p_message)
            printf(" \"%s\"\n", context->p_message);
        else
            printf(" *%s\n", context->filename ? context->filename : "stdin");
        return;
    }

    if (context->filename) {
        printf("%s(%s)= ", ((ft_ssl_algorithm_t *)context->entry.data)->upper_name, context->filename);
    } else if (IS_OPTION_S(context->options) && file != stdin) {
        printf("%s(\"%s\")= ", ((ft_ssl_algorithm_t *)context->entry.data)->upper_name, context->p_message);
    } else if (IS_OPTION_P(context->options)) {
        if (context->p_message) {
            printf("(\"%s\")= ", context->p_message);
        }
        // Don't print anything here as the (stdin)= part is already printed by process_input
    } else {
        printf("%s(stdin)= ", ((ft_ssl_algorithm_t *)context->entry.data)->upper_name);
    }

    print_hash(context);
    printf("\n");
}

void process_input(ft_ssl_context_t * context, FILE * file, void (*pad)(uint8_t *, size_t *, size_t), void (*update)(uint8_t *, size_t, uint32_t *)) {

    if (file == stdin && IS_OPTION_P(context->options))
        write(1, "(\"", 2);

    size_t read_bytes = 0;
    bool was_full_chunk = false;

    while ((read_bytes = fread(context->chunk, 1, CHUNK_SIZE_READ, file)) > 0) {
        context->chunk_size = read_bytes;
        context->message_size += read_bytes;
        was_full_chunk = (read_bytes == CHUNK_SIZE_READ);

        if (read_bytes < CHUNK_SIZE_READ) {
            // Last chunk: do final padding
            pad(context->chunk, &context->chunk_size, context->message_size);
            update(context->chunk, context->chunk_size, context->hash);
        } else if (file == stdin) {
            // If reading from stdin, just process the chunk
            update(context->chunk, context->chunk_size, context->hash);
        } else {
            // For regular files, we can safely check for EOF
            if (fgetc(file) == EOF) {
                pad(context->chunk, &context->chunk_size, context->message_size);
                update(context->chunk, context->chunk_size, context->hash);
            } else {
                fseek(file, -1, SEEK_CUR);
                update(context->chunk, context->chunk_size, context->hash);
            }
        }

        if (file == stdin && IS_OPTION_P(context->options))
            write(1, context->chunk, read_bytes);
    }

    // Handle empty stream or final padding for stdin
    if (context->message_size == 0 || (file == stdin && was_full_chunk)) {
        context->chunk_size = 0;
        pad(context->chunk, &context->chunk_size, context->message_size);
        update(context->chunk, context->chunk_size, context->hash);
    }

    if (file == stdin && IS_OPTION_P(context->options))
        write(1, "\")= ", 4);
}