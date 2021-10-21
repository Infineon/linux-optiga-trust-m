/*
MIT License

Copyright (c) 2018 Oleg Yamnikov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "shared_mutex.h"
#include <errno.h> // errno, ENOENT
#include <fcntl.h> // O_RDWR, O_CREATE
#include <linux/limits.h> // NAME_MAX
#include <sys/mman.h> // shm_open, shm_unlink, mmap, munmap,
                      // PROT_READ, PROT_WRITE, MAP_SHARED, MAP_FAILED
#include <unistd.h> // ftruncate, close
#include <stdio.h> // perror
#include <stdlib.h> // malloc, free
#include <string.h> // strcpy

pthread_mutex_t shm_lock;

shared_mutex_t shared_mutex_init(const char *name) 
{
  shared_mutex_t mutex = {NULL, 0, NULL, 0,NULL};
  trustm_mutex_t *addr;
  trustm_mutex_t *mutex_ptr;

  // Open existing shared memory object, or create one.
  // Two separate calls are needed here, to mark fact of creation
  // for later initialization of pthread mutex.
  TRUSTM_MUTEX_DBGFN(">");
  TRUSTM_MUTEX_DBGFN("pthread lock");
  pthread_mutex_lock(&shm_lock); 
  TRUSTM_MUTEX_DBGFN("pthread lock successfully");
  mutex.shm_fd = shm_open(name, O_RDWR, 0660);
  if (mutex.shm_fd == -1 && errno == ENOENT) {
    mutex.shm_fd = shm_open(name, O_RDWR|O_CREAT, 0660);
    mutex.created = 1;
    TRUSTM_MUTEX_DBGFN("create new shm");
  }
  TRUSTM_MUTEX_DBGFN("pthread unlock");
  pthread_mutex_unlock(&shm_lock); 
  TRUSTM_MUTEX_DBGFN("pthread unlock successfully");
  if (mutex.shm_fd == -1) {
    perror("shm_open");
    return mutex;
  }
  TRUSTM_MUTEX_DBGFN("truncate shm ");
  // Truncate shared memory segment so it would contain
  // trustm_mutex_t.
  if (ftruncate(mutex.shm_fd, sizeof(trustm_mutex_t)) != 0) {
    perror("ftruncate");
    return mutex;
  }

  // Map pthread mutex into the shared memory.
    addr = mmap(
    NULL,
    sizeof(trustm_mutex_t),
    PROT_READ|PROT_WRITE,
    MAP_SHARED,
    mutex.shm_fd,
    0
  );
  
  if (addr == MAP_FAILED) {
    perror("mmap");
    return mutex;
  }
  mutex_ptr = addr;

  // If shared memory was just initialized -
  // initialize the mutex as well.
  
  
  if (mutex.created) {
    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr)) {
      perror("pthread_mutexattr_init");
      return mutex;
    }
    if (pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)) {
      perror("pthread_mutexattr_setpshared");
      return mutex;
    }
    
    if (pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST)) {
      perror("pthread_mutexattr_setrobust");
      return mutex;
      
    }
 
    
    if (pthread_mutex_init(&mutex_ptr->mutex, &attr)) {
      perror("pthread_mutex_init");
      return mutex;
    }
  }
  TRUSTM_MUTEX_DBGFN("-----> mutes ptr:%x", &mutex_ptr->mutex);
#ifdef DEBUG_TRUSTM_MUTEX  
  for(int i = 0; i < sizeof(pthread_mutex_t); i++)
    {
        printf("%x",((char*)&mutex_ptr->mutex)[i]);
    }
  printf("\n");
#endif  
  mutex.ptr = &mutex_ptr->mutex;
  mutex.pid = &mutex_ptr->pid;
  mutex.name = (char *)malloc(NAME_MAX+1);
  strcpy(mutex.name, name);
  TRUSTM_MUTEX_DBGFN("<");
  return mutex;
}

int shared_mutex_close(shared_mutex_t mutex) {
  if (munmap((void *)mutex.ptr, sizeof(pthread_mutex_t))) {
    perror("munmap");
    return -1;
  }
  mutex.ptr = NULL;
  if (close(mutex.shm_fd)) {
    perror("close");
    return -1;
  }
  mutex.shm_fd = 0;
  free(mutex.name);
  return 0;
}

int shared_mutex_destroy(shared_mutex_t mutex) {
  if ((errno = pthread_mutex_destroy(mutex.ptr))) {
    perror("pthread_mutex_destroy");
    return -1;
  }
  if (munmap((void *)mutex.ptr, sizeof(pthread_mutex_t))) {
    perror("munmap");
    return -1;
  }
  mutex.ptr = NULL;
  if (close(mutex.shm_fd)) {
    perror("close");
    return -1;
  }
  mutex.shm_fd = 0;
  if (shm_unlink(mutex.name)) {
    perror("shm_unlink");
    return -1;
  }
  free(mutex.name);
  return 0;
}

