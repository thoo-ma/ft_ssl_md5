#!/bin/bash

run_test_files() {
  local algo=$1
  shift
  for file in "$@"; do
    openssl $algo $file
    ./ft_ssl $algo $file
    echo ''
  done
}

run_test_stdin() {
  local algo=$1
  local input=$2
  echo "$input" | openssl $algo
  echo "$input" | ./ft_ssl $algo
  echo ''
}

run_test_files md5 readme Makefile
run_test_stdin md5 '42 is nice'

run_test_files sha256 readme Makefile
run_test_stdin sha256 '42 is nice'