#!/bin/bash

# ___________________ MD5 ___________________

openssl  md5 readme
./ft_ssl md5 readme
echo ''

openssl  md5 Makefile
./ft_ssl md5 Makefile
echo ''

openssl  md5 readme Makefile
./ft_ssl md5 readme Makefile
echo ''

echo '42 is nice' | openssl  md5
echo '42 is nice' | ./ft_ssl md5
echo ''

# ___________________ SHA256 ________________

echo '42 is nice' | openssl  sha256
echo '42 is nice' | ./ft_ssl sha256
echo ''

openssl  sha256 readme
./ft_ssl sha256 readme
echo ''

openssl  sha256 Makefile
./ft_ssl sha256 Makefile
echo ''

openssl  sha256 readme Makefile
./ft_ssl sha256 readme Makefile