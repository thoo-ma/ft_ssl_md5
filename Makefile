CC = clang

CFLAGS = -Wall -Wextra -Werror

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

.PHONY: all clean fclean re