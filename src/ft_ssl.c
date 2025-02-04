#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>

#include "md5.h"
#include "sha256.h"
#include "ft_ssl.h"

// static void print_context(ft_ssl_context_t * context) {
//     printf("hash type: %s\n", context->entry.key);
//     printf("options: %d\n", context->options);
//     printf("filename: %s\n", context->filename);
//     printf("message length: %ld\n", context->message_len);
//     printf("words number: %d\n", context->words_number);
// }

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
        printf("%s(%s)= ", context->entry.key, context->filename);
        print_hash(context);
        printf("\n");
    } else if (context->options & OPTION_P) {
        printf("(\"%s\")= ", context->message);
        print_hash(context);
        printf("\n");
    } else {
        printf("(stdin)= ");
        print_hash(context);
        printf("\n");
    }
}

void do_md5(ft_ssl_context_t * context) {

    // DEBUG
    // print_context(context);

    // 1. pad
    uint64_t padded_len = 0;
    char * padded_message = md5_padding(context->message, (uint64_t)context->message_len, &padded_len);
    if (!padded_message) {
        printf("Error: memory allocation failed\n");
        free(context->message);
        exit(EXIT_FAILURE);
    }

    // 2. hash
    memcpy(context->hash, md5(padded_message, padded_len), context->words_number * sizeof(uint32_t));

    // 3. print
    ft_ssl_print(context);

    // 4. free
    free(padded_message);
}

void do_sha256(ft_ssl_context_t * context) {

    // DEBUG
    // print_context(context);

    // 1. pad
    uint8_t * padded_message = sha256_padding(context->message);
    if (!padded_message) {
        printf("Error: memory allocation failed\n");
        free(context->message);
        exit(EXIT_FAILURE);
    }

    // 2. hash
    memcpy(context->hash, sha256(padded_message), context->words_number * sizeof(uint32_t));

    // 3. print
    ft_ssl_print(context);

    // 4. free
    free(padded_message);
}

int main(int ac, char ** av) {

    if (ac < 2)
        return exit_error(print_usage, av[0]);

    // Initialize the hash table
    int table_size = 2;
    if (hcreate((size_t)table_size) == 0)
        return exit_error(perror, "hcreate");

    // Insert key-function pointer pairs into the hash table
    ENTRY item;
    for (int i = 0; i < table_size; i++) {
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
        .message = NULL,
        .message_len = 0,
        .hash = {0},
        .words_number = !strcmp(item_found->key, "md5") ? 4 : 8
    };

    // Parse the options
    int opt;
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
                if (optind < ac) {
                    context.message = strdup(av[optind]);
                    context.message_len = (long)strlen(context.message);
                    optind++;
                } else return exit_error(print_missing_argument, av[0]);
                break;
            default: return exit_error(print_usage, av[0]);
        }
    }

    if (context.options & OPTION_S) {

        // Always print message with -s option
        SET_OPTION_P(context.options);

        // Call the hash function for the -s option
        ((hash_function_t)context.entry.data)(&context);
        free(context.message);

        // Exit if no additional files are provided
        if (++optind >= ac)
            return EXIT_SUCCESS;
        else {
            optind--;
            context.message = NULL;
            context.message_len = 0;
            UNSET_OPTION_P(context.options);
        }
    }

    if (++optind < ac) {
        for (int i = optind; i < ac; i++) {

            // Open from file
            FILE *file = fopen(av[i], "rb");
            if (!file) {
                perror(av[i]);
                continue;
            }
            context.filename = av[i];

            // Determine the file size
            fseek(file, 0, SEEK_END);
            context.message_len = ftell(file);
            fseek(file, 0, SEEK_SET);

            // Allocate memory for the file content
            context.message = malloc((size_t)context.message_len + 1);
            if (!context.message) {
                perror("malloc");
                fclose(file);
                continue;
            }

            /// @todo read by chunks
            // Read the file content into the buffer
            fread(context.message, 1, (size_t)context.message_len, file);
            context.message[context.message_len] = '\0';
            fclose(file);

            // Call the hash function
            ((hash_function_t)context.entry.data)(&context);

            free(context.message);
            context.message = NULL;
        }
    } else {

        /// @todo
        // Allocate a buffer for the message
        size_t buffer_size = 4096;
        context.message = malloc(buffer_size + 1);
        if (!context.message)
            return exit_error(perror, "malloc");

        // Read from standard input to the buffer
        context.message_len = (long)fread(context.message, 1, buffer_size, stdin);
        context.message[context.message_len] = '\0';

        // Call the hash function
        ((hash_function_t)context.entry.data)(&context);

        free(context.message);
    }

    return EXIT_SUCCESS;
}
