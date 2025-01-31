#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>

#include "md5.h"
#include "sha256.h"

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

            uint64_t padded_len = 0;
            if (!strcmp(hash_type, "md5")) {
                // Padding the input
                char * padded_input = md5_padding(input, file_size, &padded_len);
                if (!padded_input) {
                    printf("Error: memory allocation failed\n");
                    free(input);
                    return EXIT_FAILURE;
                }
                uint32_t * h = md5(padded_input, padded_len);
                printf("MD5(%s)= %08x%08x%08x%08x\n", av[i], h[0], h[1], h[2], h[3]);
                free(input);
                free(padded_input);
            } else {
                // Padding the input
                uint8_t * padded_input = sha256_padding(input);
                if (!padded_input) {
                    printf("Error: memory allocation failed\n");
                    free(input);
                    return EXIT_FAILURE;
                }
                uint32_t * h = sha256(padded_input);
                printf("SHA256(%s)= %08x%08x%08x%08x%08x%08x%08x%08x\n", av[i], h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
                free(input);
                free(padded_input);
            }
        }
    } else {
        // Read from standard input
        char input[4096];
        size_t input_len = fread(input, 1, sizeof(input) - 1, stdin);
        input[input_len] = '\0';

        // Padding the input
        uint64_t padded_len2 = 0;
        uint32_t * h;
        if (!strcmp(hash_type, "md5")) {
            char * padded_input = md5_padding(input, input_len, &padded_len2);
            if (!padded_input) {
                printf("Error: memory allocation failed\n");
                return EXIT_FAILURE;
            }
            h = md5(padded_input, padded_len2);
            printf("(stdin)= %08x%08x%08x%08x\n",  h[0], h[1], h[2], h[3]);
            free(padded_input);
        } else {
            uint8_t * padded_input = sha256_padding(input);
            if (!padded_input) {
                printf("Error: memory allocation failed\n");
                return EXIT_FAILURE;
            }
            uint32_t * h = sha256(padded_input);
            printf("(stdin)= %08x%08x%08x%08x%08x%08x%08x%08x\n", h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
            free(padded_input);
        }
    }

    return EXIT_SUCCESS;
}
