NAME=ft_nmap
CC=cc
CFLAGS=-Wall -Wextra -Werror -g
RM= rm -rf

SRC=main.c
OBJ=$(patsubst %.c,%.o,$(SRC))
DEP=$(patsubst %.c,%.d,$(SRC))

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -pthread -o $(NAME)

%.c:

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.d: %.c
	$(CC) $(CFLAGS) -MM -o $@ $<

clean:
	$(RM) $(OBJ) $(DEP)

fclean: clean
	$(RM) $(NAME)

re: fclean all

.PHONY: re all clean fclean

-include $(DEP)
