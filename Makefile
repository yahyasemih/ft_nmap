NAME=ft_nmap
CC=cc
CFLAGS=-Wall -Wextra -Werror -g
RM= rm -rf

SRC=ft_nmap.c thread_utils.c printing_utils.c options_utils.c net_utils.c scan_utils.c utilities.c
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
