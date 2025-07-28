// read_test.c — triggers .read path (ext4 should support it)
#include <fcntl.h>  // for O_RDONLY
#include <stdio.h>  // for perror, printf
#include <unistd.h> // for open, read, close, ssize_t

int main() {
  int fd = open("testfile.txt", O_RDONLY);
  if (fd < 0) {
    perror("open");
    return 1;
  }

  char buf[100];
  ssize_t bytes = read(fd, buf, sizeof(buf));

  if (bytes < 0)
    perror("read");
  else
    printf("Read %zd bytes\n", bytes);

  close(fd);
  return 0;
}
