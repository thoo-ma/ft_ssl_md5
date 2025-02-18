CC = clang

CFLAGS = -Wall -Wextra -Werror -Wconversion

SRCS = src/ft_ssl.c src/md5.c src/sha256.c

HEADERS = src/ft_ssl.h src/md5.h src/sha256.h

OBJS = $(SRCS:.c=.o)

NAME = ft_ssl

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $(NAME) $^

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(NAME) $(OBJS)

fclean: clean
	$(RM) $(NAME)

re: fclean all

debug: CFLAGS += -DDEBUG
debug: re

test: test_md5 test_sha256

test_md5: all
	@expect -f expect.sh md5

test_sha256: all
	@expect -f expect.sh sha256

tidy:
	clang-tidy --quiet $(SRCS) -- $(CFLAGS)

.PHONY: all clean fclean re test test_md5 test_sha256 debug tidy