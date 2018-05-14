#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <time.h>
#include <limits.h>

#include "picohttpparser/picohttpparser.h"
#define CACHE_POLICY_NO_CACHE 0
#define CACHE_POLICY_RANDOM 1
#define CACHE_POLICY_NRU 2

#ifndef CACHE_POLICY
#define CACHE_POLICY CACHE_POLICY_RANDOM
#endif

SSL_CTX* ctx;
char* document_root;

typedef struct cache_node {
  pthread_mutex_t mutex;
  char* path;
  char* contents;
  size_t size;
  time_t time_added;
  bool used;
  struct cache_node* next;
} cache_node_t;

#define MAX_CACHE_SIZE 2
pthread_mutex_t cache_size_mutex = PTHREAD_MUTEX_INITIALIZER;
size_t cache_size;
cache_node_t* cache[MAX_CACHE_SIZE] = {0};
pthread_mutex_t cache_bucket_mutexes[MAX_CACHE_SIZE];

int nru_current_bucket = 0;
cache_node_t* nru_current_node = NULL;
cache_node_t* nru_prev_node = NULL;

unsigned int hash_randomizer;

unsigned int power_mod(unsigned int base, unsigned int expt) {
  // Make it a long to prevent overflow
  unsigned long power = 1;
  for (unsigned int i = 0; i < expt; i++) {
    power = (power * base) % UINT_MAX;
  }

  return power;
}

#define BIG_PRIME 7349

// pre: hash_randomizer is initialized to a random value
unsigned int hash(char* string) {
  // Make it a long to prevent overflow
  unsigned long sum = 0;
  size_t string_len = strlen(string);
  for (size_t i = 0; i < string_len; i++) {
    sum += string[i] * power_mod(BIG_PRIME, i);
    sum %= UINT_MAX;
  }

  return sum ^ hash_randomizer;
}

void kick_node (cache_node_t* node_to_kick, cache_node_t* prev, int bucket_index) {
  printf("Kicking: %s\n", node_to_kick->path);
  if (node_to_kick == nru_current_node) {
    nru_current_node = nru_current_node->next;
  } else if (node_to_kick == nru_prev_node) {
    nru_prev_node = prev;
  }
  pthread_mutex_lock(&node_to_kick->mutex);
  if (prev == NULL) {
    cache[bucket_index] = node_to_kick->next;
  } else {
    prev->next = node_to_kick->next;
  }
  pthread_mutex_unlock(&node_to_kick->mutex);
  free(node_to_kick->path);
  free(node_to_kick->contents);
  free(node_to_kick);
}

void cache_kick_random (void) {
  int rand_index = rand() % MAX_CACHE_SIZE;
  pthread_mutex_lock(&cache_bucket_mutexes[rand_index]);
  cache_node_t* node_to_kick = cache[rand_index];
  while (node_to_kick == NULL) {
    pthread_mutex_unlock(&cache_bucket_mutexes[rand_index]);
    rand_index++;
    rand_index %= MAX_CACHE_SIZE;
    pthread_mutex_lock(&cache_bucket_mutexes[rand_index]);
    node_to_kick = cache[rand_index];
  }
  kick_node(node_to_kick, NULL, rand_index);
  pthread_mutex_unlock(&cache_bucket_mutexes[rand_index]);
  cache_size--;
}

void cache_kick_nru (void) {  
  pthread_mutex_lock(&cache_bucket_mutexes[nru_current_bucket]);
  cache_node_t* current = nru_current_node;
  cache_node_t* prev = nru_prev_node;
  while (true) {
    while (current == NULL) {
      pthread_mutex_unlock(&cache_bucket_mutexes[nru_current_bucket]);
      nru_current_bucket = (nru_current_bucket+1)%MAX_CACHE_SIZE;
      pthread_mutex_lock(&cache_bucket_mutexes[nru_current_bucket]);
      current = cache[nru_current_bucket];
      prev = NULL;
    }
    while (current != NULL) {
      if (current->used == true) {
        current->used = false;
      } else {
        // remove the item
        kick_node(current, prev, nru_current_bucket);
        pthread_mutex_unlock(&cache_bucket_mutexes[nru_current_bucket]);
        nru_current_bucket++;
        return;
      }
      current = current->next;
    }
  }
}

// cache_add takes ownership of path and contents, which should be created with
// malloc
void cache_add(char* path, char* contents, size_t size) {
  cache_node_t* new = malloc(sizeof(cache_node_t));
  pthread_mutex_init(&new->mutex, NULL);
  new->path = path;
  new->contents = contents;
  new->size = size;
  new->used = true;
  new->time_added = time(NULL);
  
  pthread_mutex_lock(&cache_size_mutex);
  cache_size++;
  
  if (cache_size > MAX_CACHE_SIZE) {
    if (CACHE_POLICY == CACHE_POLICY_RANDOM) {
      cache_kick_random();
    } else {
      cache_kick_nru();
    }
  }
  pthread_mutex_unlock(&cache_size_mutex);

  unsigned int index = hash(path) % MAX_CACHE_SIZE;
  pthread_mutex_lock(&cache_bucket_mutexes[index]);

  new->next = cache[index];
  cache[index] = new;

  pthread_mutex_unlock(&cache_bucket_mutexes[index]);
}

// cache_get returns a locked node that should be unlocked with cache_unlock when done
cache_node_t* cache_get(char* path) {
  unsigned int index = hash(path) % MAX_CACHE_SIZE;
  pthread_mutex_lock(&cache_bucket_mutexes[index]);

  cache_node_t* curr;
  cache_node_t* prev = NULL;
  for (curr = cache[index]; curr != NULL; curr = curr->next) {
    if (strcmp(curr->path, path) == 0) {
      // Check if this item in the cache is stale, if so, remove it
      int MAX_AGE_SEC = 60*30;
      if ((time(NULL) - curr->time_added)>MAX_AGE_SEC) {
        kick_node (curr, prev, index);
        curr = NULL;
      } else {
        pthread_mutex_lock(&curr->mutex);
        curr->used = true;
      }
      break;
 
    }
    prev = curr;
  }
  
  pthread_mutex_unlock(&cache_bucket_mutexes[index]);

  return curr;
}

void cache_unlock(cache_node_t* node) {
  if (node != NULL) {
    pthread_mutex_unlock(&node->mutex);
  }
}

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

  char* path_string = malloc(strlen(document_root) + path_len + 1);
  strcpy(path_string, document_root);
  strncat(path_string, path, path_len);

  printf("path string: %s\n", path_string);
  cache_node_t* cached_file = NULL;
  bool stat_fail = false;
  bool is_executable = false;
  size_t size;
  if (CACHE_POLICY != CACHE_POLICY_NO_CACHE) {
    cached_file = cache_get(path_string);
  }
  
  if (cached_file == NULL) {
    struct stat file_stat;
    stat_fail = stat(path_string, &file_stat) != 0;
    
    is_executable = file_stat.st_mode & S_IXOTH;
    size = file_stat.st_size;
  } else {
    printf("Cache contained %s\n", path_string);
    size = cached_file->size;
  }

  if (stat_fail) {
    char* response =
      "HTTP/1.1 404 Not Found\r\n"
      "Content-Type: text/plain\r\n"
      "Content-Length: 9\r\n"
      "\r\n"
      "Not Found\r\n"
      ;

    SSL_write(ssl, response, strlen(response));
  } else if (is_executable) {
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
        cache_unlock(cached_file);
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
  } else {
    FILE* file = fopen(path_string, "r");
    if (file == NULL) {
      fprintf(stderr, "Couldn't open file\n");
      cache_unlock(cached_file);
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
      size
             );

    SSL_write(ssl, response_headers, strlen(response_headers));

    if (cached_file == NULL) {
      char* file_buffer = malloc(size);
      if (fread(file_buffer, 1, size, file) != size) {
        perror("fread error.\n");
        cache_unlock(cached_file);
        return -1;
      }
      SSL_write(ssl, file_buffer, size);
      if (CACHE_POLICY != CACHE_POLICY_NO_CACHE) {
        printf("Adding %s to the cache.\n", path_string);
        cache_add(path_string, file_buffer, size);
      }
    } else {
      SSL_write(ssl, cached_file->contents, cached_file->size);
    }
  }
  cache_unlock(cached_file);
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

  srand(time(NULL));
  hash_randomizer = rand() % UINT_MAX;

  for (int i = 0; i < MAX_CACHE_SIZE; i++) {
    pthread_mutex_init(&cache_bucket_mutexes[i], NULL);
  }

  switch (CACHE_POLICY) {
  case CACHE_POLICY_NO_CACHE:
    printf("Cache disabled.\n");
    break;
  case CACHE_POLICY_NRU:
    printf("NRU cache enabled.\n");
    break;
  case CACHE_POLICY_RANDOM:
    printf("Random cache enabled.\n");
    break;
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
