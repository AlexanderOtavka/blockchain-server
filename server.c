#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <sys/stat.h>

#include "picohttpparser/picohttpparser.h"

SSL_CTX* ctx;

int handle_request (SSL* ssl) {
  char buf[4096];
  const char *method, *path;
  int pret, minor_version;
  struct phr_header headers[100];
  size_t buflen = 0, prevbuflen = 0, method_len, path_len, num_headers;
  ssize_t rret;

  while (1) {
    /* read the request */
    while ((rret = SSL_read(ssl, buf + buflen, sizeof(buf) - buflen)) == -1
           && errno == EINTR);
    if (rret <= 0)
      return -1;
    prevbuflen = buflen;
    buflen += rret;
    /* parse the request */
    num_headers = sizeof(headers) / sizeof(headers[0]);
    pret = phr_parse_request(buf, buflen, &method, &method_len, &path,
                             &path_len, &minor_version, headers, &num_headers,
                             prevbuflen);
    if (pret > 0)
      break; /* successfully parsed the request */
    else if (pret == -1)
      return -1;
    /* request is incomplete, continue the loop */
    assert(pret == -2);
    if (buflen == sizeof(buf))
      return -1;
  }

  printf("request is %d bytes long\n", pret);
  printf("method is %.*s\n", (int)method_len, method);
  printf("path is %.*s\n", (int)path_len, path);
  printf("HTTP version is 1.%d\n", minor_version);
  printf("headers:\n");
  for (int i = 0; i != num_headers; ++i) {
    printf("%.*s: %.*s\n", (int)headers[i].name_len, headers[i].name,
           (int)headers[i].value_len, headers[i].value);
  }

  char path_string[path_len + 1];
  strncpy(path_string, path, path_len);

  FILE* file = fopen(path_string, "r");
  if (file == NULL) {
    char * response =
      "HTTP/1.1 404 Not Found\r\n"
      "Content-Type: text/plain\r\n"
      "Content-Length: 9\r\n"
      "\r\n"
      "Not Found\r\n"
      ;

    SSL_write(ssl, response, strlen(response));
  } else {
    fseek(file, 0L, SEEK_END);
    size_t file_size = ftell(file);
    rewind(file);

    char response_headers[1000];

    snprintf(
      response_headers,
      sizeof(response_headers),
      "HTTP/1.1 404 Not Found\r\n"
      "Content-Type: text/plain\r\n"
      "Content-Length: %lu\r\n"
      "\r\n",
      file_size
    );

    SSL_write(ssl, response_headers, strlen(response_headers));

    char file_buffer[0x100];
    size_t bytes_read;
    while ((bytes_read = fread(file_buffer, 1, sizeof(file_buffer), file)) > 0) {
      SSL_write(ssl, response_headers, bytes_read);
    }
  }

  return 0;
}

typedef struct connection_handler_thread_arg {
  int client;
} connection_handler_thread_arg_t;

void* connection_handler_thread_fn(void* void_arg) {
  connection_handler_thread_arg_t* args = (connection_handler_thread_arg_t*) void_arg;
  int client = args->client;
  free(args);

  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, client);

  if (SSL_accept(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
  } else {
    handle_request(ssl);
  }

  SSL_free(ssl);
  close(client);

  return NULL;
}

int create_socket(int port)
{
  int s;
  struct sockaddr_in addr;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    perror("Unable to create socket");
    exit(EXIT_FAILURE);
  }

  if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    perror("Unable to bind");
    exit(EXIT_FAILURE);
  }

  if (listen(s, 1) < 0) {
    perror("Unable to listen");
    exit(EXIT_FAILURE);
  }

  return s;
}

void init_openssl()
{ 
  SSL_load_error_strings();	
  OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
  EVP_cleanup();
}

SSL_CTX *create_context()
{
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = TLS_server_method();

  ctx = SSL_CTX_new(method);

  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
  if (!ctx) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return ctx;
}

int main(int argc, char **argv)
{
  if (argc != 2) {
    fprintf(stderr, "usage: server <document root>\n");
    exit(EXIT_FAILURE);
  }

  char* document_root = argv[1];
  struct stat stat_buffer;
  if (stat(document_root, &stat_buffer) != 0) {
    fprintf(stderr, "Could not open document root\n");
    exit(EXIT_FAILURE);
  } else if (!S_ISDIR(stat_buffer.st_mode)) {
    fprintf(stderr, "Document root is not a directory\n");
    exit(EXIT_FAILURE);
  }

  init_openssl();
  ctx = create_context();

  SSL_CTX_set_ecdh_auto(ctx, 1);

  /* Set the key and cert */
  if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  // Now that we have read the keys we can change the root
  chroot(document_root);

  int sock = create_socket(4433);

  /* Handle connections */
  while(1) {
    struct sockaddr_in addr;
    uint len = sizeof(addr);

    int client = accept(sock, (struct sockaddr*)&addr, &len);
    if (client < 0) {
      perror("Unable to accept");
      exit(EXIT_FAILURE);
    }

    connection_handler_thread_arg_t* args = malloc(sizeof(connection_handler_thread_arg_t));
    args->client = client;

    pthread_t thread;
    pthread_create(&thread, NULL, connection_handler_thread_fn, args);
  }

  close(sock);
  SSL_CTX_free(ctx);
  cleanup_openssl();
}
