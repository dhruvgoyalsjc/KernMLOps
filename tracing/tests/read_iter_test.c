// read_iter_test.c — uses pipe (usually backed by read_iter)
#include <stdio.h>  // for printf() and perror()
#include <string.h> // for strlen()
#include <unistd.h> // for pipe(), read(), write(), close(), and ssize_t

int main() {
  int pipefd[2];
  if (pipe(pipefd) == -1) {
    perror("pipe");
    return 1;
  }

  const char* msg = "pipe read test";
  ssize_t bytes_written = write(pipefd[1], msg, strlen(msg));
  if (bytes_written < 0) {
    perror("write");
    return 1;
  }

  char buf[100];
  ssize_t bytes = read(pipefd[0], buf, sizeof(buf));

  if (bytes < 0) {
    perror("read");
    return 1;
  } else
    printf("Read %zd bytes from pipe\n", bytes);

  close(pipefd[0]);
  close(pipefd[1]);
  return 0;
}
