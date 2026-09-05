#include "server_st.h"


int make_socket_non_blocking (FILE* fp, int sfd){
  int flags, s;

  flags = fcntl (sfd, F_GETFL, 0);
  if (flags == -1)
    {
      fprintf(fp, "fcntl get");
      fflush(fp);
      return -1;
    }

  flags |= O_NONBLOCK;
  s = fcntl (sfd, F_SETFL, flags);
  if (s == -1)
    {
      fprintf(fp, "fcntl set");
      fflush(fp);
      return -2;
    }

  return 0;
}