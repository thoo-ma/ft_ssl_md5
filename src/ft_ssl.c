#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>

#include "md5.h"

void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [md5|sha256] [-p] [-q] [-r] [-s] [file...]\n", prog_name);
}

int main(int ac, char ** av) {

    if (ac < 2) {
        print_usage(av[0]);
        return EXIT_FAILURE;
    }

    if (strcmp(av[1], "md5") != 0 && strcmp(av[1], "sha256") != 0) {
        print_usage(av[0]);
        return EXIT_FAILURE;
    }

    int opt;
    while ((opt = getopt(ac, av, "pqrs")) != -1) {
        switch (opt) {
            case 'p':
                printf("Option -p\n");
                break;
            case 'q':
                printf("Option -q\n");
                break;
            case 'r':
                printf("Option -r\n");
                break;
            case 's':
                printf("Option -s\n");
                break;
            default:
                printf("No option\n");
                break;
        }
    }

    // After getopt, optind points to the first non-option argument
    const char *hash_type = av[optind++]; // increment to skip the hash type
    printf("Hash type: %s\n", hash_type);

    if (optind < ac) {
        for (int i = optind; i < ac; i++) {

            FILE *file = fopen(av[i], "rb");
            if (!file) {
                perror(av[i]);
                continue;
            }

            // Determine the file size
            fseek(file, 0, SEEK_END);
            long file_size = ftell(file);
            fseek(file, 0, SEEK_SET);

            // Allocate memory for the file content
            char *input = malloc(file_size + 1);
            if (!input) {
                perror("malloc");
                fclose(file);
                continue;
            }

            // Read the file content into the buffer
            fread(input, 1, file_size, file);
            input[file_size] = '\0';

            fclose(file);

            // Padding the input
            char * padded_input = md5_padding(input);
            if (!padded_input) {
                printf("Error: memory allocation failed\n");
                free(input);
                return EXIT_FAILURE;
            }

            // printf("input = %s\n", padded_input);
            uint32_t * h = md5(padded_input);
            printf("MD5(%s)= %08x%08x%08x%08x\n", av[i], h[0], h[1], h[2], h[3]);
            free(input);
            free(padded_input);
        }
    } else {
        print_usage(av[0]);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}