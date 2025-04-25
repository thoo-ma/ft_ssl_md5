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

test_unit: test_md5 test_sha256

test_md5: all venv
	@cd test && .venv/bin/python -m pytest -v tests.py --algorithm=md5

test_sha256: all venv
	@cd test && .venv/bin/python -m pytest -v tests.py --algorithm=sha256

test_fuzz: test_fuzz_md5 test_fuzz_sha256

test_fuzz_md5: all venv
	@cd test && .venv/bin/python -m pytest -v test_fuzz.py --algorithm=md5

test_fuzz_sha256: all venv
	@cd test && .venv/bin/python -m pytest -v test_fuzz.py --algorithm=sha256

test: test_unit test_fuzz

# HELP ##########################################################################

help:
	@echo "Available targets:"
	@echo "  all ............ Build the ft_ssl binary (default)"
	@echo "  clean .......... Remove object files"
	@echo "  fclean ......... Remove binary, object files, and test artifacts"
	@echo "  re ............. Rebuild the project"
	@echo "  format ......... Format code with clang-format"
	@echo "  tidy ........... Check code with clang-tidy"
	@echo "  venv ........... Create/update Python virtual environment for tests"
	@echo "  test ........... Run all unit and fuzz tests"
	@echo "  test_unit ...... Run all unit tests (MD5 & SHA256)"
	@echo "  test_md5 ....... Run MD5 unit tests"
	@echo "  test_sha256 .... Run SHA256 unit tests"
	@echo "  test_fuzz ...... Run all fuzz tests (MD5 & SHA256)"
	@echo "  test_fuzz_md5 .. Run MD5 fuzz tests"
	@echo "  test_fuzz_sha256 Run SHA256 fuzz tests"
	@echo "  help ........... Show this help message"

.PHONY: all clean fclean re test test_unit test_md5 test_sha256 test_fuzz test_fuzz_md5 test_fuzz_sha256 tidy format help venv