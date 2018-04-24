CC = clang

CFLAGS = -g `pkg-config --libs openssl`

all: server

server: server.c
	$(CC) $(CFLAGS) -o server server.c

clean:
	rm -f server
