#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Wrap open()
int __real_open(const char *pathname, int flags, mode_t mode);

int __wrap_open(const char *pathname, int flags, mode_t mode) {
  int fd = __real_open(pathname, flags, mode);
  if (fd == -1) {
    __builtin_trap(); // crash immediately
  }
  return fd;
}

// Wrap fopen()
FILE *__real_fopen(const char *path, const char *mode);

FILE *__wrap_fopen(const char *path, const char *mode) {
  FILE *fp = __real_fopen(path, mode);
  if (!fp) {
    __builtin_trap(); // crash immediately
  }
  return fp;
}
