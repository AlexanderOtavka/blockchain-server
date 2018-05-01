CC = clang

CFLAGS = -g
SSLFLAGS = `pkg-config --libs openssl`

all: server

server: server.o parser.o
	$(CC) $(CFLAGS) $(SSLFLAGS) -o build/server build/server.o build/parser.o

server.o: server.c
	$(CC) $(CFLAGS) -c -o build/server.o server.c

parser.o: picohttpparser/picohttpparser.c
	$(CC) $(CFLAGS) -c -o build/parser.o picohttpparser/picohttpparser.c

clean:
	rm -rf build
