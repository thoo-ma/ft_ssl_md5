#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>

#include "md5.h"
#include "sha256.h"
#include "ft_ssl.h"

void do_md5(ft_ssl_context_t * context) {

    // DEBUG
    printf("hash type: %s\n", context->entry.key);
    printf("options: %d\n", context->options);
    printf("filename: %s\n", context->filename);
    printf("message length: %ld\n", context->message_len);

    // 1. pad
    uint64_t padded_len = 0;
    char * padded_message = md5_padding(context->message, context->message_len, &padded_len);
    if (!padded_message) {
        printf("Error: memory allocation failed\n");
        free(context->message);
        exit(EXIT_FAILURE);
    }

    // 2. hash
    uint32_t * h = md5(padded_message, padded_len);

    // 3. print
    context->filename
    ? printf("MD5(%s)= %08x%08x%08x%08x\n", context->filename, h[0], h[1], h[2], h[3])
    : printf("(stdin)= %08x%08x%08x%08x\n", h[0], h[1], h[2], h[3]);

    free(padded_message);

    // uint32_t *h = md5(padded_input);
    // if (p_flag)
    //     printf("(\"%.*s\")= %08x%08x%08x%08x\n", (int)strlen(input) - 1, input, h[0], h[1], h[2], h[3]);
    // else if (r_flag)
    //     printf("%08x%08x%08x%08x \"%s\"\n", h[0], h[1], h[2], h[3], input);
    // else
    //     printf("(stdin)= %08x%08x%08x%08x\n", h[0], h[1], h[2], h[3]);
    // free(padded_input);
}

void do_sha256(ft_ssl_context_t * context) {

    // DEBUG
    printf("hash type: %s\n", context->entry.key);
    printf("options: %d\n", context->options);
    printf("filename: %s\n", context->filename);
    printf("message length: %ld\n", context->message_len);

    // 1. pad
    uint8_t * padded_message = sha256_padding(context->message);
    if (!padded_message) {
        printf("Error: memory allocation failed\n");
        free(context->message);
        exit(EXIT_FAILURE);
    }

    // 2. hash
    uint32_t * h = sha256(padded_message);

    // 3. print
    context->filename
    ? printf("SHA256(%s)= %08x%08x%08x%08x%08x%08x%08x%08x\n", context->filename, h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7])
    : printf("(stdin)= %08x%08x%08x%08x%08x%08x%08x%08x\n", h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

    free(padded_message);
}

void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [md5|sha256] [-p] [-q] [-r] [-s] [file...]\n", prog_name);
}

int main(int ac, char ** av) {

    if (ac < 2) {
        print_usage(av[0]);
        return EXIT_FAILURE;
    }

    // Initialize the hash table
    int table_size = 2;
    if (hcreate(table_size) == 0) {
        perror("hcreate");
        exit(EXIT_FAILURE);
    }

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
    if (!item_found) {
        print_usage(av[0]);
        return EXIT_FAILURE;
    }

    // Initialize the context
    ft_ssl_context_t context = {
        .entry = *item_found,
        .options = 0,
        .filename = NULL,
        .message = NULL,
        .message_len = 0
    };

    // Parse the options
    int opt;
    while ((opt = getopt(ac, av, "pqrs")) != -1) {
        switch (opt) {
            case 'p':
                SET_OPTION_P(context.options);
                printf("Option -p\n");
                break;
            case 'q':
                SET_OPTION_Q(context.options);
                printf("Option -q\n");
                break;
            case 'r':
                SET_OPTION_R(context.options);
                printf("Option -r\n");
                break;
            case 's':
                SET_OPTION_S(context.options);
                printf("Option -s\n");
                break;
            default:
                print_usage(av[0]);
                return EXIT_FAILURE;
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
            context.message = malloc(context.message_len + 1);
            if (!context.message) {
                perror("malloc");
                fclose(file);
                continue;
            }

            /// @todo read by chunks
            // Read the file content into the buffer
            fread(context.message, 1, context.message_len, file);
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
        if (!context.message) {
            perror("malloc");
            return EXIT_FAILURE;
        }

        // Read from standard input to the buffer
        size_t message_len = fread(context.message, 1, buffer_size, stdin);
        printf("message_len: %ld\n", message_len);
        context.message[message_len] = '\0';

        /// @todo cast
        context.message_len = (long)message_len;

        // Call the hash function
        ((hash_function_t)context.entry.data)(&context);

        free(context.message);
    }

    return EXIT_SUCCESS;
}
