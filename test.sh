#!/bin/bash

echo -n 'foo' | openssl md5
# echo -n 'foo' | ./ft_ssl md5
./ft_ssl 'foo'

# echo -n 'foo' | openssl sha256
# echo -n 'foo' | ./ft_ssl sha256
# ./ft_ssl 'foo'