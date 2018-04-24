CC = clang

CFLAGS = -g
SSLFLAGS = `pkg-config --libs openssl`

all: server

server: server.o parser.o
	$(CC) $(CFLAGS) $(SSLFLAGS) -o server server.o parser.o

server.o: server.c
	$(CC) $(CFLAGS) -c -o server.o server.c

parser.o: picohttpparser/picohttpparser.c
	$(CC) $(CFLAGS) -c -o parser.o picohttpparser/picohttpparser.c

clean:
	rm -f server
