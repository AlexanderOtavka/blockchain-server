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
#include <stdbool.h>
#include <sys/wait.h>


#include "picohttpparser/picohttpparser.h"

SSL_CTX* ctx;
char* document_root;

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
    if (rret <= 0) {
      fprintf(stderr, "failed to read\n");
      return -1;
    }
    prevbuflen = buflen;
    buflen += rret;
    /* parse the request */
    num_headers = sizeof(headers) / sizeof(headers[0]);
    pret = phr_parse_request(buf, buflen, &method, &method_len, &path,
                             &path_len, &minor_version, headers, &num_headers,
                             prevbuflen);
    if (pret > 0)
      break; /* successfully parsed the request */
    else if (pret == -1) {
      fprintf(stderr, "failed to parse\n");
      return -1;
    }
    /* request is incomplete, continue the loop */
    assert(pret == -2);
    if (buflen == sizeof(buf)) {
      fprintf(stderr, "request too large\n");
      return -1;
    }
  }

  //printf("request is %d bytes long\n", pret);
  //printf("method is %.*s\n", (int)method_len, method);
  //printf("path is %.*s\n", (int)path_len, path);
  //printf("HTTP version is 1.%d\n", minor_version);
  //printf("headers:\n");
  //for (int i = 0; i != num_headers; ++i) {
  //  printf("%.*s: %.*s\n", (int)headers[i].name_len, headers[i].name,
  //         (int)headers[i].value_len, headers[i].value);
  //}

  char path_string[strlen(document_root) + path_len + 1];
  strcpy(path_string, document_root);
  strncat(path_string, path, path_len);

  printf("path string: %s\n", path_string);

  struct stat file_stat;
  bool stat_fail = stat(path_string, &file_stat) != 0;

  if (stat_fail) {
    char* response =
      "HTTP/1.1 404 Not Found\r\n"
      "Content-Type: text/plain\r\n"
      "Content-Length: 9\r\n"
      "\r\n"
      "Not Found\r\n"
      ;

    SSL_write(ssl, response, strlen(response));
  } else if (file_stat.st_mode & S_IXOTH) {
    // We are looking at an executable, so run it
    int pipes[2][2];
    pipe(pipes[0]);
    pipe(pipes[1]);
    int child_read_fd = pipes[0][0];
    int child_write_fd = pipes[1][1];
    
    int parent_read_fd = pipes[1][0];
    int parent_write_fd = pipes[0][1];

    // read the request into child read
    write(parent_write_fd, buf, sizeof(char)*buflen);
    
    int pid = fork();
    if (pid == 0) {
      
      dup2(child_read_fd, STDIN_FILENO);
      dup2(child_write_fd, STDOUT_FILENO);

      close(child_read_fd);
      close(child_write_fd);
      close(parent_read_fd);
      close(parent_write_fd);
      char * args[] = {path_string, NULL};

      if (execvp(args[0], args) == -1) {
        fprintf(stderr, "Invalid executable.\n");
        return -1;
      }
    } else {
      close(child_read_fd);
      close(child_write_fd);
      // Send executable's output to the client
      char write_buf[256];
      while (read(parent_read_fd, write_buf, sizeof(write_buf)-1)) {
        SSL_write(ssl, write_buf, strlen(write_buf));
      }
      waitpid(pid, NULL, 0);
    }
    /*
    char buf[256];
    buf[255] = '\0';
    FILE * output = popen(path_string, "r");
    fseek(output, 0L, SEEK_END);
    int size = ftell(output);
    rewind(output);
    char response[1000];
    snprintf(
             response,
             sizeof(response),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: text/plain\r\n"
             "Content-Length: %d\r\n"
             "\r\n",
             size
             );
    SSL_write(ssl, response, strlen(response));
    if (output != NULL) {
      while (fread(buf, sizeof(char), 255, output) > 0) {
        SSL_write(ssl, buf, strlen(buf));
      }
    } else {
      return -1;
    }
    pclose(output);   
    */      
  } else {
    FILE* file = fopen(path_string, "r");
    if (file == NULL) {
      fprintf(stderr, "Server error\n");
      return -1;
    }

    char* file_extension = strrchr(path_string, '.');
    char* mime_type;
    if (file_extension == NULL) {
      mime_type = "text/plain";
    } else if (strcmp(file_extension, ".html") == 0) {
      mime_type = "text/html";
    } else if (strcmp(file_extension, ".json") == 0) {
      mime_type = "application/json";
    } else if (strcmp(file_extension, ".js") == 0) {
      mime_type = "application/javascript";
    } else if (strcmp(file_extension, ".css") == 0) {
      mime_type = "text/css";
    } else {
      mime_type = "text/plain";
    }

    char response_headers[1000];
    snprintf(
      response_headers,
      sizeof(response_headers),
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: %s\r\n"
      "Content-Length: %lu\r\n"
      "\r\n",
      mime_type,
      file_stat.st_size
    );

    SSL_write(ssl, response_headers, strlen(response_headers));

    char file_buffer[0x100];
    size_t bytes_read;
    while ((bytes_read = fread(file_buffer, 1, sizeof(file_buffer), file)) > 0) {
      SSL_write(ssl, file_buffer, bytes_read);
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
    int handle_ret = handle_request(ssl);
    if (handle_ret == -1) {
      char* response =
        "HTTP/1.1 500 Server Error\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 21\r\n"
        "\r\n"
        "Internal Server Error\r\n"
        ;

      SSL_write(ssl, response, strlen(response));
    }
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

  document_root = strdup(argv[1]);
  if (document_root[strlen(document_root) - 1] == '/') {
    document_root[strlen(document_root) - 1] = '\0';
  }

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
