#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include "md5.h"
#include "sha256.h"
#include "ft_ssl.h"

const ft_ssl_algorithm_t algorithms[] = {
    {"md5",    "MD5",    4, md5},
    {"sha256", "SHA256", 8, sha256},
    {NULL, NULL, 0, NULL}
};

static void __attribute__((unused)) print_context(ft_ssl_context_t * context) {
    printf("hash type: %s\n", ((ft_ssl_algorithm_t *)context->entry.data)->lower_name);
    printf("options: %d\n", context->options);
    printf("filename: %s\n", context->filename);
    printf("message size: %ld\n", context->message_size);
    printf("chunk size: %ld\n", context->chunk_size);
    printf("chunk: %s\n", (char *)context->chunk);
}

static void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [md5|sha256] [-p] [-q] [-r] [-s string] [file...]\n", prog_name);
}

static void print_missing_argument(const char *prog_name) {
    fprintf(stderr, "%s: option -s requires an argument\n", prog_name);
}

static int exit_error(void (*f)(const char *), const char *prog_name) {
    f(prog_name);
    return EXIT_FAILURE;
}

static void print_hash(ft_ssl_context_t *context) {
    for (size_t i = 0; i < ((ft_ssl_algorithm_t *)context->entry.data)->word_count; i++)
        printf("%08x", context->hash[i]);
}

static void ft_ssl_print(ft_ssl_context_t *context) {

    if (IS_OPTION_Q(context->options)) {
        print_hash(context);
        printf("\n");
        return;
    }

    if (IS_OPTION_R(context->options)) {
        print_hash(context);
        printf(" *%s\n", context->filename ? context->filename : "stdin");
        return;
    }

    if (context->filename) {
        printf("%s(%s)= ", ((ft_ssl_algorithm_t *)context->entry.data)->upper_name, context->filename);
    } else if (context->p_message && IS_OPTION_P(context->options)) {
        printf("(\"%s\")= ", context->p_message);
    } else {
        printf("(stdin)= ");
    }

    print_hash(context);
    printf("\n");
}

void sha256(ft_ssl_context_t * context, FILE * file) {

    // init sha256 state
    context->hash[0] = sha256_context.h0;
    context->hash[1] = sha256_context.h1;
    context->hash[2] = sha256_context.h2;
    context->hash[3] = sha256_context.h3;
    context->hash[4] = sha256_context.h4;
    context->hash[5] = sha256_context.h5;
    context->hash[6] = sha256_context.h6;
    context->hash[7] = sha256_context.h7;

    if (!IS_OPTION_S(context->options) && IS_OPTION_P(context->options) && !IS_OPTION_R(context->options) && !IS_OPTION_Q(context->options))
        write(1, "(\"", 2);

    size_t read_bytes = 0;
    int was_full_chunk = 0;

    while ((read_bytes = fread(context->chunk, 1, CHUNK_SIZE_READ, file)) > 0) {
        context->chunk_size = read_bytes;
        context->message_size += read_bytes;
        was_full_chunk = (read_bytes == CHUNK_SIZE_READ);

        if (read_bytes < CHUNK_SIZE_READ) {
            // last chunk -> do final padding
            sha256_padding(context->chunk, &context->chunk_size, context->message_size);
            sha256_update(context->chunk, context->chunk_size, context->hash);
        } else {
            // If reading from stdin, just process the chunk
            if (file == stdin) {
                sha256_update(context->chunk, context->chunk_size, context->hash);
            } else {
                // For regular files, we can safely check for EOF
                if (fgetc(file) == EOF) {
                    sha256_padding(context->chunk, &context->chunk_size, context->message_size);
                    sha256_update(context->chunk, context->chunk_size, context->hash);
                } else {
                    fseek(file, -1, SEEK_CUR);
                    sha256_update(context->chunk, context->chunk_size, context->hash);
                }
            }
        }

        if (!IS_OPTION_S(context->options) && IS_OPTION_P(context->options) && !IS_OPTION_R(context->options) && !IS_OPTION_Q(context->options))
            write(1, context->chunk, read_bytes);
    }

    // Handle empty stream or final padding for stdin
    if (context->message_size == 0 || (file == stdin && was_full_chunk)) {
        context->chunk_size = 0;
        sha256_padding(context->chunk, &context->chunk_size, context->message_size);
        sha256_update(context->chunk, context->chunk_size, context->hash);
    }

    if (!IS_OPTION_S(context->options) && IS_OPTION_P(context->options) && !IS_OPTION_R(context->options) && !IS_OPTION_Q(context->options))
        write(1, "\")= ", 4);

    ft_ssl_print(context);
}

void md5(ft_ssl_context_t * context, FILE * file) {

    // init md5 state
    context->hash[0] = md5_context.h0;
    context->hash[1] = md5_context.h1;
    context->hash[2] = md5_context.h2;
    context->hash[3] = md5_context.h3;

    if (!context->filename && IS_OPTION_P(context->options) && !IS_OPTION_S(context->options) && !IS_OPTION_R(context->options) && !IS_OPTION_Q(context->options))
        write(1, "(\"", 2);

    size_t read_bytes = 0;
    int was_full_chunk = 0;

    while ((read_bytes = fread(context->chunk, 1, CHUNK_SIZE_READ, file)) > 0) {
        context->chunk_size = read_bytes;
        context->message_size += read_bytes;
        was_full_chunk = (read_bytes == CHUNK_SIZE_READ);

        if (read_bytes < CHUNK_SIZE_READ) {
            // last chunk -> do final padding
            md5_padding(context->chunk, &context->chunk_size, context->message_size);
            md5_update(context->chunk, context->chunk_size, context->hash);
        } else {
            // If reading from stdin, just process the chunk
            if (file == stdin) {
                md5_update(context->chunk, context->chunk_size, context->hash);
            } else {
                // For regular files, we can safely check for EOF
                if (fgetc(file) == EOF) {
                    md5_padding(context->chunk, &context->chunk_size, context->message_size);
                    md5_update(context->chunk, context->chunk_size, context->hash);
                } else {
                    fseek(file, -1, SEEK_CUR);
                    md5_update(context->chunk, context->chunk_size, context->hash);
                }
            }
        }

        if (!context->filename && IS_OPTION_P(context->options) && !IS_OPTION_S(context->options) && !IS_OPTION_R(context->options) && !IS_OPTION_Q(context->options))
            write(1, context->chunk, read_bytes);
    }

    // Handle empty stream or final padding for stdin
    if (context->message_size == 0 || (file == stdin && was_full_chunk)) {
        context->chunk_size = 0;
        md5_padding(context->chunk, &context->chunk_size, context->message_size);
        md5_update(context->chunk, context->chunk_size, context->hash);
    }

    if (!context->filename && IS_OPTION_P(context->options) && !IS_OPTION_S(context->options) && !IS_OPTION_R(context->options) && !IS_OPTION_Q(context->options))
        write(1, "\")= ", 4);

    md5_final(context->hash);

    ft_ssl_print(context);
}

int main(int ac, char ** av) {

    if (ac < 2)
        return exit_error(print_usage, av[0]);

    // Initialize the hash table
    size_t table_size = 2;
    if (hcreate(table_size) == 0)
        return exit_error(perror, "hcreate");

    // Insert key-function pointer pairs into the hash table
    ENTRY item;
    for (size_t i = 0; i < table_size; i++) {
        item.key = (char *)algorithms[i].lower_name;
        item.data = (ft_ssl_algorithm_t *)&algorithms[i];
        hsearch(item, ENTER);
    }

    // Check if the hash type is valid
    item.key = av[optind];
    item.data = NULL;
    ENTRY * item_found = hsearch(item, FIND);
    if (!item_found)
        return exit_error(print_usage, av[0]);

    // Skip the hash name argument
    optind++;

    // Initialize the context
    ft_ssl_context_t context = {
        .entry = *item_found,
        .options = 0,
        .filename = NULL,
        .message_size = 0,
        .hash = {0},
        .chunk = {0},
        .chunk_size = 0,
    };

    // Parse the options
    int opt;
    while ((opt = getopt(ac, av, "+pqrs:")) != -1) {
        switch (opt) {
            case 'p':
                SET_OPTION_P(context.options);
                break;
            case 'q':
                SET_OPTION_Q(context.options);
                break;
            case 'r':
                SET_OPTION_R(context.options);
                break;
            case 's':
                SET_OPTION_S(context.options);
                if (!optarg)
                    return exit_error(print_missing_argument, av[0]);
                context.p_message = optarg;
                break;
            default: return exit_error(print_usage, av[0]);
        }
    }

    // Read from stdin
    if (!isatty(fileno(stdin))) {
        ((ft_ssl_algorithm_t *)item_found->data)->f(&context, stdin);
    }

    // Read from string
    if (IS_OPTION_S(context.options)) {

        /// @todo
        // Setup the context
        SET_OPTION_P(context.options);

        // Open from memory
        FILE *file = fmemopen((void *)context.p_message, strlen(context.p_message), "rb");
        if (!file)
            exit_error(perror, "fmemopen");

        // Hash the message
        ((ft_ssl_algorithm_t *)item_found->data)->f(&context, file);

        // Close the file stream
        fclose(file);

        UNSET_OPTION_P(context.options);
    }

    // Read from file
    if (optind < ac) {
        for (int i = optind; i < ac; i++) {

            // Setup the context
            context.message_size = 0;
            context.filename = av[i];
            // context.p_message = NULL;
            // UNSET_OPTION_S(context.options);

            // Open from file
            FILE *file = fopen(av[i], "rb");
            if (!file) {
                perror(av[i]);
                continue;
            }

            // Hash the message
            ((ft_ssl_algorithm_t *)item_found->data)->f(&context, file);

            // Close the file stream
            fclose(file);
        }
    }

    return EXIT_SUCCESS;
}
