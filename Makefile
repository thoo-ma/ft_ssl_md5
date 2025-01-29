CC = clang

CFLAGS = -Wall -Wextra -Werror

SRCS = src/ft_ssl.c src/md5.c

HEADERS = src/md5.h

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

test: all
	openssl  md5 Makefile Makefile
	./ft_ssl md5 Makefile Makefile

.PHONY: all clean fclean re test