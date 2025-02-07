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

const hash_type_t hash_types[] = { "md5", "sha256" };

const hash_function_t hash_functions[] = { md5, sha256 };

static void __attribute__((unused)) print_context(ft_ssl_context_t * context) {
    printf("hash type: %s\n", context->entry.key);
    printf("options: %d\n", context->options);
    printf("filename: %s\n", context->filename);
    printf("message length: %ld\n", context->message_len);
    printf("words number: %d\n", context->words_number);
    printf("message chunk length: %ld\n", context->message_chunk_len);
    printf("message chunk: %s\n", (char *)context->message_chunk);
}

static void to_uppercase(const char *src, char *dest, size_t size) {
    for (size_t i = 0; i < size - 1 && src[i] != '\0'; i++)
        dest[i] = (char)toupper((unsigned char) src[i]);
    dest[size - 1] = '\0';
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

static void print_hash(ft_ssl_context_t * context) {
    for (size_t i = 0; i < context->words_number; i++)
        printf("%08x", context->hash[i]);
}

static void ft_ssl_print(ft_ssl_context_t *context) {

    /// @todo do uppercase in place (only used once)
    /// @todo set this number dynamically
    // 7 cause the longest hash type is "sha256"
    char algo_name[7] = {0};
    to_uppercase(context->entry.key, algo_name, 7);

    if (context->options & OPTION_Q) {
        print_hash(context);
        printf("\n");
    } else if (context->options & OPTION_R) {
        print_hash(context);
        context->filename
        ? printf(" *%s\n", context->filename)
        : printf(" *stdin\n");
    } else if (context->filename) {
        // printf("%s(%s)= ", context->entry.key, context->filename);
        printf("%s(%s)= ", algo_name, context->filename);
        print_hash(context);
        printf("\n");
    } else if (context->options & OPTION_P) {
        if (context->p_message)
            printf("(\"%s\")= ", *context->p_message);
        print_hash(context);
        printf("\n");
    } else {
        printf("(stdin)= ");
        print_hash(context);
        printf("\n");
    }
}

void sha256(ft_ssl_context_t * context, FILE * file) {

    // init sha256 state
    context->hash[0] = 0x6a09e667;
    context->hash[1] = 0xbb67ae85;
    context->hash[2] = 0x3c6ef372;
    context->hash[3] = 0xa54ff53a;
    context->hash[4] = 0x510e527f;
    context->hash[5] = 0x9b05688c;
    context->hash[6] = 0x1f83d9ab;
    context->hash[7] = 0x5be0cd19;

    if (!IS_OPTION_S(context->options) && IS_OPTION_P(context->options) && !IS_OPTION_R(context->options) && !IS_OPTION_Q(context->options))
        write(1, "(\"", 2);

    size_t read_bytes = 0;
    while ((read_bytes = fread(context->message_chunk, 1, CHUNK_SIZE_READ, file)) > 0) {
        context->message_chunk_len = read_bytes;
        context->message_len += read_bytes;

        if (read_bytes < CHUNK_SIZE_READ) {
            // last chunk -> do final padding
            sha256_padding(context->message_chunk, &context->message_chunk_len, context->message_len);
            sha256_update(context->message_chunk, context->message_chunk_len, context->hash);
        } else {
            // check if there's more data to read
            if (fgetc(file) == EOF) {
                // last chunk -> do final padding
                sha256_padding(context->message_chunk, &context->message_chunk_len, context->message_len);
                sha256_update(context->message_chunk, context->message_chunk_len, context->hash);
            } else {
                // not the last chunk -> no padding, just hash
                fseek(file, -1, SEEK_CUR);
                sha256_update(context->message_chunk, context->message_chunk_len, context->hash);
            }
        }

        if (!IS_OPTION_S(context->options) && IS_OPTION_P(context->options) && !IS_OPTION_R(context->options) && !IS_OPTION_Q(context->options))
            write(1, context->message_chunk, read_bytes);
    }

    /// @todo
    // handle empty stream
    if (context->message_len == 0) {
        printf("empty stream\n");
        ((hash_function_t)context->entry.data)(context, file);
    }

    if (!IS_OPTION_S(context->options) && IS_OPTION_P(context->options) && !IS_OPTION_R(context->options) && !IS_OPTION_Q(context->options))
        write(1, "\")= ", 4);

    ft_ssl_print(context);
}

void md5(ft_ssl_context_t * context, FILE * file) {

    // init md5 state
    context->hash[0] = 0x67452301;
    context->hash[1] = 0xEFCDAB89;
    context->hash[2] = 0x98BADCFE;
    context->hash[3] = 0x10325476;

    if (!IS_OPTION_S(context->options) && IS_OPTION_P(context->options) && !IS_OPTION_R(context->options) && !IS_OPTION_Q(context->options))
        write(1, "(\"", 2);

    size_t read_bytes = 0;
    while ((read_bytes = fread(context->message_chunk, 1, CHUNK_SIZE_READ, file)) > 0) {
        context->message_chunk_len = read_bytes;
        context->message_len += read_bytes;

        if (read_bytes < CHUNK_SIZE_READ) {
            // last chunk -> do final padding
            md5_padding(context->message_chunk, &context->message_chunk_len, context->message_len);
            md5_update(context->message_chunk, context->message_chunk_len, context->hash);

        } else {
            // check if there's more data to read
            if (fgetc(file) == EOF) {
                // last chunk -> do final padding
                md5_padding(context->message_chunk, &context->message_chunk_len, context->message_len);
                md5_update(context->message_chunk, context->message_chunk_len, context->hash);
            } else {
                // not the last chunk -> no padding, just hash
                fseek(file, -1, SEEK_CUR);
                md5_update(context->message_chunk, context->message_chunk_len, context->hash);
            }
        }

        if (!IS_OPTION_S(context->options) && IS_OPTION_P(context->options) && !IS_OPTION_R(context->options) && !IS_OPTION_Q(context->options))
            write(1, context->message_chunk, read_bytes);
    }

    /// @todo
    // handle empty stream
    if (context->message_len == 0) {
        printf("empty stream\n");
        ((hash_function_t)context->entry.data)(context, file);
    }

    if (!IS_OPTION_S(context->options) && IS_OPTION_P(context->options) && !IS_OPTION_R(context->options) && !IS_OPTION_Q(context->options))
        write(1, "\")= ", 4);

    /// @todo
    memcpy(context->hash, md5_final(context->hash), context->words_number * sizeof(uint32_t));

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
        item.key = hash_types[i];
        item.data = hash_functions[i];
        hsearch(item, ENTER);
    }

    // Check if the hash type is valid
    item.key = av[optind];
    item.data = NULL;
    ENTRY * item_found = hsearch(item, FIND);
    if (!item_found)
        return exit_error(print_usage, av[0]);

    // Initialize the context
    ft_ssl_context_t context = {
        .entry = *item_found,
        .options = 0,
        .filename = NULL,
        .message_len = 0,
        .hash = {0},
        .words_number = !strcmp(item_found->key, "md5") ? 4 : 8, /// @todo
        .message_chunk = {0},
        .message_chunk_len = 0,
    };

    // Parse the options
    int opt, s_message;
    while ((opt = getopt(ac, av, "pqrs")) != -1) {
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
                s_message = optind;
                if (optind >= ac)
                    return exit_error(print_missing_argument, av[0]);
                break;
            default: return exit_error(print_usage, av[0]);
        }
    }

    // Read from stdin
    if (!isatty(fileno(stdin))) {
        ((hash_function_t)context.entry.data)(&context, stdin);
    }

    // Read from string
    if (IS_OPTION_S(context.options)) {

        // Setup the context
        SET_OPTION_P(context.options);
        context.p_message = &av[s_message];

        // Open from memory
        FILE *file = fmemopen((void *)av[s_message], strlen(av[s_message]), "rb");
        if (!file)
            exit_error(perror, "fmemopen");

        // Hash the message
        ((hash_function_t)context.entry.data)(&context, file);

        // Close the file stream
        fclose(file);

        optind += 2;
        if (optind >= ac)
            return EXIT_SUCCESS;
        else {
            optind--;
            context.message_len = 0;
            UNSET_OPTION_P(context.options);
        }
    }

    // Read from file
    if (++optind < ac) {
        for (int i = optind; i < ac; i++) {

            // Setup the context
            context.message_len = 0;
            context.filename = av[i];

            // Open from file
            FILE *file = fopen(av[i], "rb");
            if (!file) {
                perror(av[i]);
                continue;
            }

            // Hash the message
            ((hash_function_t)context.entry.data)(&context, file);

            // Close the file stream
            fclose(file);
        }
    }

    return EXIT_SUCCESS;
}
