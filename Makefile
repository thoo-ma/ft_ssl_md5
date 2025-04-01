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

fclean: clean
	$(RM) $(NAME)

re: fclean all

# DEVELOPMENT TARGETS ###########################################################

debug: CFLAGS += -DDEBUG
debug: re

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

test: test_md5 test_sha256

test_md5: all venv
	@cd test && .venv/bin/python -m pytest -v tests.py --algorithm=md5

test_sha256: all venv
	@cd test && .venv/bin/python -m pytest -v tests.py --algorithm=sha256

# HELP ##########################################################################

help:
	@echo "Available targets:"
	@echo "  all       : Build the ft_ssl binary (default)"
	@echo "  clean     : Remove object files"
	@echo "  fclean    : Remove binary and object files"
	@echo "  re        : Rebuild the project"
	@echo "  debug     : Build with debug symbols"
	@echo "  venv      : Create a Python virtual environment for tests"
	@echo "  test      : Run all tests"
	@echo "  test_md5  : Run MD5 tests"
	@echo "  test_sha256: Run SHA-256 tests"
	@echo "  tidy      : Check code with clang-tidy"
	@echo "  format    : Format code with clang-format"
	@echo "  help      : Show this help message"

.PHONY: all clean fclean re test test_md5 test_sha256 debug tidy format help venv