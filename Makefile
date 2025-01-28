CC = clang

CFLAGS = -Wall -Wextra -Werror

SRCS = md5.c

OBJS = $(SRCS:.c=.o)

NAME = ft_ssl

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $(NAME) $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(NAME) $(OBJS)

fclean: clean
	$(RM) $(NAME)

re: fclean all

.PHONY: all clean fclean re