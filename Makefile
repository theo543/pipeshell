CC ?= gcc
CFLAGS ?= -O0 -g -fsanitize=address,undefined -Wall -Wextra -pedantic

pipeshell: pipeshell.c
	$(CC) $(CFLAGS) -o $@ $<

.PHONY = clean

clean:
	rm -f pipeshell
