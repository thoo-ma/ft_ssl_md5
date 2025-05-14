# CONFIGURATION ##################################################################

CC = clang

CFLAGS = -Wall \
         -Wextra \
         -Werror \
         -Wconversion \
         -Wunreachable-code \
         -Wformat=2 \
         -Wcast-qual \
         -Wcast-align \
         -Wstrict-aliasing \
         -Wpointer-arith \
         -Wshadow \
         -Wuninitialized \
         -Wundef \
         -Wwrite-strings \
         -Wdouble-promotion \
         -fstack-protector-strong \
		 -O2

# FILES #########################################################################

SRCS = src/ft_ssl.c src/md5.c src/sha256.c src/utils.c

HEADERS = src/ft_ssl.h src/md5.h src/sha256.h src/utils.h

OBJS = $(SRCS:.c=.o)

NAME = ft_ssl

# MAIN TARGETS ##################################################################

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $(NAME) $^

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# CLEANING ######################################################################

clean:
	$(RM) $(OBJS)

fclean:
	$(RM) $(OBJS) $(NAME)
	rm -rf test/.venv
	rm -rf test/input/

re: fclean all

# CODE QUALITY ##################################################################

format:
	@clang-format -i $(SRCS) $(HEADERS)

tidy:
	clang-tidy -header-filter=.* $(SRCS) -- $(CFLAGS)

# TESTING #######################################################################

venv:
	@if [ ! -d "test/.venv" ]; then \
		python -m venv test/.venv; \
		./test/.venv/bin/python -m pip install --upgrade pip; \
		./test/.venv/bin/pip install -r test/requirements.txt; \
	fi

# Subject tests
test_subject_md5: all venv
	@cd test && .venv/bin/python -m pytest -v subject.py --algorithm=md5

test_subject_sha256: all venv
	@cd test && .venv/bin/python -m pytest -v subject.py --algorithm=sha256

test_subject: test_subject_md5 test_subject_sha256

# Fuzzing tests
test_fuzzing_md5: all venv
	@cd test && .venv/bin/python -m pytest -v fuzzing.py --algorithm=md5

test_fuzzing_sha256: all venv
	@cd test && .venv/bin/python -m pytest -v fuzzing.py --algorithm=sha256

test_fuzzing: test_fuzzing_md5 test_fuzzing_sha256

# Benchmark tests
test_benchmark_md5: all venv
	@cd test && .venv/bin/python -m pytest -v benchmark.py --algorithm=md5 -s

test_benchmark_sha256: all venv
	@cd test && .venv/bin/python -m pytest -v benchmark.py --algorithm=sha256 -s

test_benchmark: test_benchmark_md5 test_benchmark_sha256

# All tests
test_md5: test_subject_md5 test_fuzzing_md5 test_benchmark_md5

test_sha256: test_subject_sha256 test_fuzzing_sha256 test_benchmark_sha256

test: test_md5 test_sha256

# HELP ##########################################################################

help:
	@echo "Available targets:"
	@echo "  all ................... Build the ft_ssl binary (default)"
	@echo "  clean ................. Remove object files"
	@echo "  fclean ................ Remove binary, object files, and test artifacts"
	@echo "  re .................... Rebuild the project"
	@echo "  format ................ Format code with clang-format"
	@echo "  tidy .................. Check code with clang-tidy"
	@echo "  venv .................. Create/update Python virtual environment for tests"
	@echo "  test .................. Run all tests (MD5 & SHA256)"
	@echo "  test_md5 .............. Run all MD5 tests"
	@echo "  test_sha256 ........... Run all SHA256 tests"
	@echo "  test_subject .......... Run format tests for both algorithms"
	@echo "  test_subject_md5 ...... Run MD5 format tests"
	@echo "  test_subject_sha256 ... Run SHA256 format tests"
	@echo "  test_fuzzing .......... Run fuzzing tests for both algorithms" 
	@echo "  test_fuzzing_md5 ...... Run MD5 fuzzing tests"
	@echo "  test_fuzzing_sha256 ... Run SHA256 fuzzing tests"
	@echo "  test_benchmark ........ Run benchmarks for both algorithms"
	@echo "  test_benchmark_md5 .... Run MD5 benchmarks"
	@echo "  test_benchmark_sha256 . Run SHA256 benchmarks"
	@echo "  help .................. Show this help message"

.PHONY: all clean fclean re test test_md5 test_sha256 test_subject test_subject_md5 test_subject_sha256 test_fuzzing test_fuzzing_md5 test_fuzzing_sha256 test_benchmark test_benchmark_md5 test_benchmark_sha256 tidy format help venv