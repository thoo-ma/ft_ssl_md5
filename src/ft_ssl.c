#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ft_ssl.h"
#include "md5.h"
#include "sha256.h"

static const ft_ssl_algorithm_t algorithms[] = {
    {"md5", "MD5", 4, md5},
    {"sha256", "SHA256", 8, sha256},
    {NULL, NULL, 0, NULL}};

static void __attribute__((unused)) print_context(ft_ssl_context_t * context) {
    printf("hash type: %s\n", ((ft_ssl_algorithm_t *)context->entry.data)->lower_name);
    printf("options: %d\n", context->options);
    printf("filename: %s\n", context->filename);
    printf("message size: %ld\n", context->message_size);
    printf("chunk size: %ld\n", context->chunk_size);
    printf("chunk: %s\n", (char *)context->chunk);
}

static void print_usage(const char * prog_name) {
    fprintf(stderr, "Usage: %s [md5|sha256] [-p] [-q] [-r] [-s string] [file...]\n", prog_name);
}

static void print_missing_argument(const char * prog_name) {
    fprintf(stderr, "%s: option -s requires an argument\n", prog_name);
}

static void exit_error(void (*f)(const char *), const char * prog_name) {
    f(prog_name);
    exit(EXIT_FAILURE);
}


static void ft_ssl_init(ft_ssl_context_t * context, int ac, char ** av) {

    if (ac < 2)
        exit_error(print_usage, av[0]);

    // Initialize the hash table
    size_t table_size = 2; // Number of algorithms
    if (hcreate(table_size) == 0)
        exit_error(perror, "hcreate");

    // Insert key-function pointer pairs into the hash table
    ENTRY item;
    for (size_t i = 0; i < table_size; i++) {
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wcast-qual"
        item.key = (char *)algorithms[i].lower_name;
        item.data = (ft_ssl_algorithm_t *)&algorithms[i];
        #pragma GCC diagnostic pop
        hsearch(item, ENTER);
    }

    // Check if the hash type is valid
    item.key = av[optind];
    ENTRY * item_found = hsearch(item, FIND);
    if (!item_found)
        exit_error(print_usage, av[0]);

    // Skip the hash name argument
    optind++;

    // Initialize the context
    memset(context, 0, sizeof(ft_ssl_context_t));
    context->entry = *item_found;

    // Parse the options
    int opt;
    while ((opt = getopt(ac, av, "+pqrs:")) != -1) {
        switch (opt) {
            case 'p':
                SET_OPTION_P(context->options);
                break;
            case 'q':
                SET_OPTION_Q(context->options);
                break;
            case 'r':
                SET_OPTION_R(context->options);
                break;
            case 's':
                SET_OPTION_S(context->options);
                if (!optarg)
                    exit_error(print_missing_argument, av[0]);
                context->p_message = optarg;
                break;
            default:
                exit_error(print_usage, av[0]);
        }
    }
}

int main(int ac, char ** av) {

    ft_ssl_context_t context;
    ft_ssl_init(&context, ac, av);

    // Read from stdin
    if (!isatty(fileno(stdin)) && (optind >= ac || IS_OPTION_P(context.options)))
        ((ft_ssl_algorithm_t *)context.entry.data)->f(&context, stdin);

    // Read from string
    if (IS_OPTION_S(context.options)) {

        // Setup the context
        context.message_size = 0;
        context.filename = NULL;

        // Open from memory
        FILE * file = fmemopen((void *)context.p_message, strlen(context.p_message), "rb");
        if (!file)
            exit_error(perror, "fmemopen");

        // Hash the message
        ((ft_ssl_algorithm_t *)context.entry.data)->f(&context, file);

        // Close the file stream
        fclose(file);
    }

    // Read from file
    if (optind < ac) {
        for (int i = optind; i < ac; i++) {

            // Setup the context
            context.message_size = 0;
            context.filename = av[i];
            context.p_message = NULL;

            // Open from file
            FILE * file = fopen(av[i], "rb");
            if (!file) {
                printf("ft_ssl: %s: %s: %s\n", ((ft_ssl_algorithm_t *)context.entry.data)->lower_name, av[i], strerror(errno));
                continue;
            }

            // Hash the message
            ((ft_ssl_algorithm_t *)context.entry.data)->f(&context, file);

            // Close the file stream
            fclose(file);
        }
    }

    hdestroy();
    return EXIT_SUCCESS;
}
