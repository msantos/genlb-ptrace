#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/resource.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <poll.h>

#include <getopt.h>

typedef struct {
  int count;
  int lfd;
  int verbose;
  size_t maxfd;
} cl_state_t;

static int cl_listen(cl_state_t *cp, const char *addr, const char *port);
static int cl_accept(cl_state_t *cp);

static const struct option long_options[] = {
    {"verbose", no_argument, NULL, 'v'}, {NULL, 0, NULL, 0}};

int main(int argc, char *argv[]) {
  cl_state_t *cp;
  struct rlimit maxfd;

  int ch = 0;

  cp = calloc(1, sizeof(cl_state_t));
  if (cp == NULL)
    err(EXIT_FAILURE, "calloc");

  if (getrlimit(RLIMIT_NOFILE, &maxfd) < 0)
    return -1;

  cp->maxfd = maxfd.rlim_cur;

  while ((ch = getopt_long(argc, argv, "v", long_options, NULL)) != -1) {
    switch (ch) {
    case 'v':
      cp->verbose++;
      break;
    default:
      errx(EXIT_FAILURE, "usage: <count> <localaddr> <localport>");
    }
  }

  argc -= optind;
  argv += optind;

  if (setvbuf(stdout, NULL, _IOLBF, 0) < 0)
    err(EXIT_FAILURE, "setvbuf");

  if (argc != 3) {
    errx(EXIT_FAILURE, "usage: <count> <localaddr> <localport>");
  }

  cp->count = atoi(argv[0]);
  if (cp->count <= 0)
    errx(EXIT_FAILURE, "usage: <count> <localaddr> <localport>");

  if (cl_listen(cp, argv[1], argv[2]) < 0)
    err(112, "listen:%s:%s", argv[1], argv[2]);

  if (cl_accept(cp) < 0)
    err(113, "accept:%s -> %s:%s", argv[0], argv[1], argv[2]);

  exit(0);
}

static int cl_accept(cl_state_t *cp) {
  struct pollfd *fds;

  fds = calloc(cp->maxfd, sizeof(struct pollfd));
  if (fds == NULL)
    return -1;

  /* listening socket */
  fds[cp->lfd].fd = cp->lfd;
  fds[cp->lfd].events = POLLIN;

  for (;;) {
    if (poll(fds, cp->maxfd, -1) < 0) {
      switch (errno) {
      case EINTR:
        continue;
      default:
        return -1;
      }
    }

    if (fds[cp->lfd].revents & (POLLERR | POLLHUP | POLLNVAL))
      return -1;

    if (fds[cp->lfd].revents & POLLIN) {
      int fd;
      struct sockaddr_storage paddr;
      socklen_t plen;
      char addrstr[INET6_ADDRSTRLEN] = {0};

      plen = sizeof(paddr);
      fd = accept(cp->lfd, (struct sockaddr *)&paddr, &plen);
      if (fd < 0)
        return -1;

      cp->count--;

      if (cp->verbose > 0) {
        switch (((struct sockaddr *)&paddr)->sa_family) {
        case AF_INET6:
          (void)fprintf(
              stderr, "accept:%d:%s:%u\n", cp->count,
              inet_ntop(AF_INET6,
                        &(((const struct sockaddr_in6 *)&paddr)->sin6_addr),
                        addrstr, sizeof(addrstr)),
              ntohs(((const struct sockaddr_in6 *)&paddr)->sin6_port));
          break;
        case AF_INET:
          (void)fprintf(
              stderr, "accept:%d:%s:%u\n", cp->count,
              inet_ntop(AF_INET,
                        &(((const struct sockaddr_in *)&paddr)->sin_addr),
                        addrstr, sizeof(addrstr)),
              ntohs(((const struct sockaddr_in *)&paddr)->sin_port));
          break;
        default:
          errno = EINVAL;
          return -1;
        }
      }

      if (close(fd) < 0)
        return -1;

      if (cp->count <= 0)
        return 0;
    }
  }
}

static int cl_listen(cl_state_t *cp, const char *addr, const char *port) {
  struct addrinfo hints = {0};
  struct addrinfo *res;
  struct addrinfo *rp;
  int s;

  int enable = 1;

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  s = getaddrinfo(addr, port, &hints, &res);
  if (s != 0) {
    (void)fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    return -1;
  }

  for (rp = res; rp != NULL; rp = rp->ai_next) {
    cp->lfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

    if (setsockopt(cp->lfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) <
        0)
      return -1;

    if (setsockopt(cp->lfd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)) <
        0)
      return -1;

    if (bind(cp->lfd, rp->ai_addr, rp->ai_addrlen) < 0)
      return -1;

    if (listen(cp->lfd, SOMAXCONN) >= 0)
      break;
  }

  freeaddrinfo(res);

  if (rp == NULL)
    return -1;

  return 0;
}
