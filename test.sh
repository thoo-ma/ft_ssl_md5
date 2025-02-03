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
  echo -n "$input" | openssl $algo
  echo -n "$input" | ./ft_ssl $algo
  echo ''
}

run_test_files_options() {
  local algo=$1
  shift
  local options=""
  while [[ $1 == -* ]]; do
    options="$options $1"
    shift
  done
  for file in "$@"; do
    openssl $algo $options $file
    ./ft_ssl $algo $options $file
    echo ''
  done
}

run_test_stdin_options() {
  local algo=$1
  shift
  local options=""
  while [[ $1 == -* ]]; do
    options="$options $1"
    shift
  done
  for input in "$@"; do
    echo -n "$input" | openssl $algo $options
    echo -n "$input" | ./ft_ssl $algo $options
    echo ''
  done
}

run_test_error() {
    local algo=$1
    ./ft_ssl $algo -z # unknown option
    ./ft_ssl $algo -s # missing argument
    ./ft_ssl $algo NonExistingFile
}

run_md5_tests() {

    # NOTE: cases with equivalent in openssl
    # no options
    run_test_files md5 readme
    run_test_stdin md5 '42 is nice'

    # -r option
    run_test_files_options md5 -r readme
    run_test_stdin_options md5 -r '42 is nice'

    # NOTE: cases with no equivalent in openssl
    # -s option
    ./ft_ssl md5 -s readme # hash the string 'readme'
    ./ft_ssl md5 -s readme readme # hash the string 'readme' and the file 'readme'
    ./ft_ssl md5 -s '42 is nice'

    # -p option (print message only when it comes from stdin)
    ./ft_ssl md5 -p readme
    echo -n '42 is nice' | ./ft_ssl md5 -p

    # -q option
    ./ft_ssl md5 -q readme
    echo -n '42 is nice' | ./ft_ssl md5 -q

    # both -r and -p should be discarded when -q is present
    ./ft_ssl md5 -q -r -p readme
    echo -n '42 is nice' | ./ft_ssl md5 -q -r -p

    # NOTE: error cases
    run_test_files_options md5 -z readme
    run_test_files_options md5 NonExistingFile
    ./ft_ssl md5 -s # missing argument
}

run_sha256_tests() {
    echo ''
}

run_md5_tests
run_sha256_tests
