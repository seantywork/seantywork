#include "server_ep.h"


int make_socket_non_blocking (int sfd){
  int flags, s;

  flags = fcntl (sfd, F_GETFL, 0);
  if (flags == -1)
    {
      perror ("fcntl get");
      return -1;
    }

  flags |= O_NONBLOCK;
  s = fcntl (sfd, F_SETFL, flags);
  if (s == -1)
    {
      perror ("fcntl set");
      return -2;
    }

  return 0;
}

bool atomic_compare_exchange(int* ptr, int compare, int exchange) {
    return __atomic_compare_exchange_n(ptr, &compare, exchange,
            0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

void atomic_store(int* ptr, int value) {
    __atomic_store_n(ptr, 0, __ATOMIC_SEQ_CST);
}

int atomic_add_fetch(int* ptr, int d) {
    return __atomic_add_fetch(ptr, d, __ATOMIC_SEQ_CST);
}

void spinlock_init(struct spinlock* spinlock) {
    atomic_store(&spinlock->locked, 0);
}

void spinlock_lock(struct spinlock* spinlock) {
    while (!atomic_compare_exchange(&spinlock->locked, 0, 1)) {
    }
}

void spinlock_unlock(struct spinlock* spinlock) {
    atomic_store(&spinlock->locked, 0);
}