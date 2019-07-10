/* Copyright 2019 Michael Santos <michael.santos@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/limits.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <sys/ptrace.h>

#include <signal.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

/* inet_ntoa() */
#include <arpa/inet.h>

/* process_vm_readv()/writev() */
#include <sys/uio.h>

#include <err.h>

#include "genlb_sandbox.h"

#if defined(__x86_64__)
#include <sys/reg.h>
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__arm__)
#define ORIG_RAX 7
#define RDI 0
#define RSI 1
#define RDX 2
#define RSP 13
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_ARM
#else
#error "seccomp: unsupported platform"
#endif

#define GENLB_VERSION "0.3.0"

#if defined(SANDBOX_null)
#define GENLB_SANDBOX "null"
#elif defined(SANDBOX_seccomp)
#define GENLB_SANDBOX "seccomp"
#endif

#define IOVEC_COUNT(_array) (sizeof(_array) / sizeof(_array[0]))

#define VERBOSE(__s, __n, ...)                                                 \
  do {                                                                         \
    if (__s->verbose >= __n) {                                                 \
      (void)fprintf(stderr, __VA_ARGS__);                                      \
    }                                                                          \
  } while (0)

typedef struct {
  int verbose;
  int connect_failure;
} genlb_state_t;

static int genlb_tracee(genlb_state_t *s, char *argv[]);
static int genlb_tracer(genlb_state_t *s, pid_t tracee);
static int genlb_connect(genlb_state_t *s, pid_t tracee);
static int genlb_socket(genlb_state_t *s, const struct sockaddr *addr,
                        socklen_t *addrlen, struct sockaddr *paddr,
                        socklen_t *paddrlen);
static int signum(int status);

static int event_loop(genlb_state_t *s);
static int read_sockaddr(genlb_state_t *s, pid_t tracee, struct sockaddr *saddr,
                         socklen_t *saddrlen);
static int write_sockaddr(genlb_state_t *s, pid_t tracee,
                          struct sockaddr *saddr, socklen_t salen);

static void usage(void);

enum { GENLB_CONNECT_FAILURE_EXIT = 0, GENLB_CONNECT_FAILURE_CONTINUE = 1 };

static const struct option long_options[] = {
    {"connect-failure", required_argument, NULL, 'c'},
    {"verbose", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}};

int main(int argc, char *argv[]) {
  pid_t pid;
  genlb_state_t *s;
  int ch;
  int rv = 0;

  s = calloc(1, sizeof(genlb_state_t));

  if (s == NULL)
    err(EXIT_FAILURE, "unable to allocate memory");

  s->connect_failure = GENLB_CONNECT_FAILURE_CONTINUE;

  while ((ch = getopt_long(argc, argv, "+c:hv", long_options, NULL)) != -1) {
    switch (ch) {
    case 'c':
      if (strcmp(optarg, "exit") == 0)
        s->connect_failure = GENLB_CONNECT_FAILURE_EXIT;
      else if (strcmp(optarg, "continue") == 0)
        s->connect_failure = GENLB_CONNECT_FAILURE_CONTINUE;
      else
        usage();
      break;
    case 'v':
      s->verbose += 1;
      break;
    case 'h':
    default:
      usage();
    }
  }

  argc -= optind;
  argv += optind;

  if (argc < 1) {
    usage();
  }

  pid = fork();

  switch (pid) {
  case -1:
    break;
  case 0:
    if (genlb_tracee(s, argv) < 0)
      err(EXIT_FAILURE, "genlb_tracee");
    exit(0);
  default:
    rv = genlb_tracer(s, pid);
  }

  exit(rv);
}

static int genlb_tracee(genlb_state_t *s, char *argv[]) {
  struct sock_filter filter[] = {
      /* Ensure the syscall arch convention is as expected. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_connect, 0, 1),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
  };

  struct sock_fprog prog = {.filter = filter,
                            .len = (unsigned short)IOVEC_COUNT(filter)};

  (void)unsetenv("LD_PRELOAD");

  if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
    VERBOSE(s, 0, "ptrace(PTRACEME): %s\n", strerror(errno));
    return -1;
  }

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
    VERBOSE(s, 0, "prctl(PR_SET_NO_NEW_PRIVS): %s\n", strerror(errno));
    return -1;
  }

  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
    VERBOSE(s, 0, "prctl(PR_SET_SECCOMP): %s\n", strerror(errno));
    return -1;
  }

  if (raise(SIGSTOP) < 0) {
    VERBOSE(s, 0, "raise(SIGSTOP): %s\n", strerror(errno));
    return -1;
  }

  return execvp(argv[0], argv);
}

static int genlb_tracer(genlb_state_t *s, pid_t tracee) {
  int status;

  if (genlb_sandbox() < 0)
    return -1;

  if (waitpid(tracee, &status, 0) < 0) {
    VERBOSE(s, 0, "waitpid: %s\n", strerror(errno));
    return -1;
  }

  if (ptrace(PTRACE_SETOPTIONS, tracee, 0,
             PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL | PTRACE_O_TRACEVFORK |
                 PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE |
                 PTRACE_O_TRACEEXEC) < 0) {
    VERBOSE(s, 0, "ptrace(SETOPTIONS): %s\n", strerror(errno));
    return -1;
  }

  if (ptrace(PTRACE_CONT, tracee, 0, 0) < 0) {
    VERBOSE(s, 0, "ptrace(CONT): %s\n", strerror(errno));
    return -1;
  }

  return event_loop(s);
}

static int event_loop(genlb_state_t *s) {
  int status;
  pid_t tracee;
  pid_t npid;

  int children = 1;

  for (;;) {
    int sig = 0;

    tracee = waitpid(-1, &status, __WALL);

    if (WIFEXITED(status)) {
      children--;
      VERBOSE(s, 2, "children=%d\n", children);

      if (children <= 0)
        return WEXITSTATUS(status);

      continue;
    }

    if (WIFSIGNALED(status)) {
      children--;
      VERBOSE(s, 2, "children=%d\n", children);

      if (children <= 0)
        return WTERMSIG(status);

      continue;
    }

    switch (status >> 8) {
    case (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8)):
      if (genlb_connect(s, tracee) < 0) {
        VERBOSE(s, 0, "genlb_connect: %s\n", strerror(errno));
        return -1;
      }

      break;

    case (SIGTRAP | (PTRACE_EVENT_FORK << 8)):
    case (SIGTRAP | (PTRACE_EVENT_VFORK << 8)):
      if (ptrace(PTRACE_GETEVENTMSG, tracee, 0, &npid) < 0) {
        VERBOSE(s, 0, "ptrace(GETEVENTMSG): %s\n", strerror(errno));
        return -1;
      }

      children++;

      if (waitpid(npid, &status, 0) < 0) {
        int oerrno = errno;
        VERBOSE(s, 1, "waitpid:%d:%s\n", npid, strerror(oerrno));
        switch (oerrno) {
        case ECHILD:
          goto GENLB_CONT;
        default:
          VERBOSE(s, 0, "waitpid:%d:%s\n", npid, strerror(oerrno));
          return -1;
        }
      }

      if (ptrace(PTRACE_SETOPTIONS, npid, 0,
                 PTRACE_ATTACH | PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL |
                     PTRACE_O_TRACEVFORK | PTRACE_O_TRACEFORK |
                     PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC) < 0) {
        int oerrno = errno;
        VERBOSE(s, 1, "waitpid:%d:%s\n", npid, strerror(oerrno));
        switch (oerrno) {
        case ESRCH:
          goto GENLB_CONT;
        default:
          VERBOSE(s, 0, "ptrace(SETOPTIONS): %s\n", strerror(errno));
          return -1;
        }
      }

      if (ptrace(PTRACE_CONT, npid, 0, 0) < 0) {
        VERBOSE(s, 0, "ptrace(CONT): %s\n", strerror(errno));
        return -1;
      }

      break;

    case (SIGTRAP | (PTRACE_EVENT_CLONE << 8)):
      if (ptrace(PTRACE_GETEVENTMSG, tracee, 0, &npid) < 0) {
        VERBOSE(s, 0, "ptrace(GETEVENTMSG): %s\n", strerror(errno));
        return -1;
      }

      children++;

      if (waitpid(npid, &status, __WALL | WNOHANG) < 0) {
        int oerrno = errno;
        VERBOSE(s, 1, "waitpid:%d:%s\n", npid, strerror(oerrno));
        switch (oerrno) {
        case ECHILD:
          goto GENLB_CONT;
        default:
          VERBOSE(s, 0, "waitpid:%d:%s\n", npid, strerror(oerrno));
          return -1;
        }
      }

      if (ptrace(PTRACE_SETOPTIONS, npid, 0,
                 PTRACE_ATTACH | PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL |
                     PTRACE_O_TRACEVFORK | PTRACE_O_TRACEFORK |
                     PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC) < 0) {
        int oerrno = errno;
        VERBOSE(s, 1, "waitpid:%d:%s\n", npid, strerror(oerrno));
        switch (oerrno) {
        case ESRCH:
          goto GENLB_CONT;
        default:
          VERBOSE(s, 0, "ptrace(SETOPTIONS): %s\n", strerror(errno));
          return -1;
        }
      }

      if (ptrace(PTRACE_CONT, npid, 0, 0) < 0) {
        VERBOSE(s, 0, "ptrace(CONT): %s\n", strerror(errno));
        return -1;
      }

      break;

    default:
      sig = signum(status);
      if (sig > 0)
        VERBOSE(s, 2, "SIGNAL:pid=%d signal=%d\n", tracee, sig);
      break;
    }

  GENLB_CONT:
    if (ptrace(PTRACE_CONT, tracee, 0, sig) < 0) {
      VERBOSE(s, 0, "ptrace(CONT): %s\n", strerror(errno));
      return -1;
    }
  }
}

static int signum(int status) {
  if (!WIFSTOPPED(status))
    return 0;

  switch (WSTOPSIG(status)) {
  case SIGSTOP:
  case SIGTRAP:
  case SIGCHLD:
  case SIGSYS:
    return 0;
  default:
    return WSTOPSIG(status);
  }
}

static int genlb_connect(genlb_state_t *s, pid_t tracee) {
  struct sockaddr_storage addr = {0};
  socklen_t addrlen = sizeof(addr);

  struct sockaddr_in paddr = {0};
  socklen_t paddrlen;
  int rv;

  if (read_sockaddr(s, tracee, (struct sockaddr *)&addr, &addrlen) < 0) {
    VERBOSE(s, 0, "read_sockaddr: %s\n", strerror(errno));
    return -1;
  }

  if (addrlen < sizeof(struct sockaddr)) {
    VERBOSE(s, 0, "read: sockaddr: addrlen=%lu/%lu\n",
            (long unsigned int)addrlen,
            (long unsigned int)sizeof(struct sockaddr));
    return -1;
  }

  switch (((const struct sockaddr *)&addr)->sa_family) {
  case AF_INET:
    if (addrlen != sizeof(struct sockaddr_in)) {
      VERBOSE(s, 0, "read: sockaddr_in: addrlen=%lu/%lu\n",
              (long unsigned int)addrlen,
              (long unsigned int)sizeof(struct sockaddr_in));
      return -1;
    }

    VERBOSE(s, 2, "connect:orig:family=%d saddr=%s port=%d\n",
            ((const struct sockaddr_in *)&addr)->sin_family,
            inet_ntoa(((const struct sockaddr_in *)&addr)->sin_addr),
            ntohs(((const struct sockaddr_in *)&addr)->sin_port));

    rv = genlb_socket(s, (const struct sockaddr *)&addr, &addrlen,
                      (struct sockaddr *)&paddr, &paddrlen);

    if (rv < 1)
      return rv;

    VERBOSE(s, 2, "connect:new:family=%d saddr=%s port=%d\n", paddr.sin_family,
            inet_ntoa(paddr.sin_addr), ntohs(paddr.sin_port));

    if (((const struct sockaddr_in *)&addr)->sin_port == paddr.sin_port &&
        ((const struct sockaddr_in *)&addr)->sin_addr.s_addr ==
            paddr.sin_addr.s_addr)
      return 0;

    if (write_sockaddr(s, tracee, (struct sockaddr *)&paddr, paddrlen) < 0) {
      VERBOSE(s, 0, "write_sockaddr: %s\n", strerror(errno));
      return -1;
    }
    break;

  case AF_INET6: {
    struct sockaddr_in sa = {0};
    socklen_t salen = sizeof(sa);
    char addrstr[INET6_ADDRSTRLEN] = {0};

    if (addrlen != sizeof(struct sockaddr_in6)) {
      VERBOSE(s, 0, "read: sockaddr_in6: addrlen=%lu/%lu\n",
              (long unsigned int)addrlen,
              (long unsigned int)sizeof(struct sockaddr_in6));
      return -1;
    }

    VERBOSE(s, 2, "connect6:orig:family=%d saddr=%s port=%d\n",
            ((const struct sockaddr_in6 *)&addr)->sin6_family,
            inet_ntop(AF_INET6,
                      &(((const struct sockaddr_in6 *)&addr)->sin6_addr),
                      addrstr, sizeof(addrstr)),
            ntohs(((const struct sockaddr_in6 *)&addr)->sin6_port));

    if (!IN6_IS_ADDR_V4MAPPED(
            &(((const struct sockaddr_in6 *)&addr)->sin6_addr)))
      return 0;

    sa.sin_family = AF_INET;
    sa.sin_port = ((const struct sockaddr_in6 *)&addr)->sin6_port;
    sa.sin_addr.s_addr =
        ((const struct sockaddr_in6 *)&addr)->sin6_addr.s6_addr32[3];

    rv = genlb_socket(s, (const struct sockaddr *)&sa, &salen,
                      (struct sockaddr *)&paddr, &paddrlen);

    if (rv < 1)
      return rv;

    VERBOSE(s, 2, "connect6:proxy:family=%d saddr=%s port=%d\n",
            paddr.sin_family, inet_ntoa(paddr.sin_addr), ntohs(paddr.sin_port));

    if (((const struct sockaddr_in6 *)&addr)->sin6_port == paddr.sin_port &&
        ((const struct sockaddr_in6 *)&addr)->sin6_addr.s6_addr32[3] ==
            paddr.sin_addr.s_addr)
      return 0;

    ((struct sockaddr_in6 *)&addr)->sin6_addr.s6_addr32[3] =
        paddr.sin_addr.s_addr;
    ((struct sockaddr_in6 *)&addr)->sin6_port = paddr.sin_port;

    VERBOSE(s, 2, "connect6:new:family=%d saddr=%s port=%d\n",
            ((const struct sockaddr_in6 *)&addr)->sin6_family,
            inet_ntop(AF_INET6,
                      &(((const struct sockaddr_in6 *)&addr)->sin6_addr),
                      addrstr, sizeof(addrstr)),
            ntohs(((const struct sockaddr_in6 *)&addr)->sin6_port));

    if (write_sockaddr(s, tracee, (struct sockaddr *)&addr, addrlen) < 0) {
      VERBOSE(s, 0, "write_sockaddr: %s\n", strerror(errno));
      return -1;
    }
  }

  break;
  default:
    break;
  }

  return 0;
}

static int genlb_socket(genlb_state_t *s, const struct sockaddr *addr,
                        socklen_t *addrlen, struct sockaddr *paddr,
                        socklen_t *paddrlen) {
  int sockfd;

  sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (sockfd < 0) {
    VERBOSE(s, 0, "socket: %s\n", strerror(errno));
    return -1;
  }

  *paddrlen = *addrlen;

  if (connect(sockfd, addr, *addrlen) < 0) {
    VERBOSE(s, 1, "connect: %s\n", strerror(errno));
    return s->connect_failure == GENLB_CONNECT_FAILURE_EXIT ? -1 : 0;
  }

  if (getpeername(sockfd, paddr, paddrlen) < 0) {
    VERBOSE(s, 0, "getpeername: %s\n", strerror(errno));
    return -1;
  }

  if (*paddrlen != *addrlen) {
    VERBOSE(s, 0, "getpeername:orig=%d bytes/new=%d bytes\n", *addrlen,
            *paddrlen);
    return -1;
  }

  if (close(sockfd) < 0) {
    VERBOSE(s, 0, "close: %s\n", strerror(errno));
    return -1;
  }

  return 1;
}

static int read_sockaddr(genlb_state_t *s, pid_t tracee, struct sockaddr *saddr,
                         socklen_t *saddrlen) {
  struct sockaddr *addr;
  socklen_t addrlen;

  struct iovec local_iov[1];
  struct iovec remote_iov[1];

  ssize_t rv;

  errno = 0;
  addr =
      (struct sockaddr *)ptrace(PTRACE_PEEKUSER, tracee, sizeof(long) * RSI, 0);
  switch (errno) {
  case 0:
    break;
  case ESRCH:
    return 0;
  default:
    return -1;
  }

  errno = 0;
  addrlen = (socklen_t)ptrace(PTRACE_PEEKUSER, tracee, sizeof(long) * RDX, 0);

  if (errno != 0)
    return -1;

  if (addrlen > *saddrlen) {
    VERBOSE(s, 0, "addrlen=%lu, saddrlen=%lu\n", (long unsigned int)addrlen,
            (long unsigned int)*saddrlen);
    errno = EINVAL;
    return -1;
  }

  local_iov[0].iov_base = saddr;
  local_iov[0].iov_len = addrlen;

  remote_iov[0].iov_base = addr;
  remote_iov[0].iov_len = addrlen;

  rv = process_vm_readv(tracee, local_iov, IOVEC_COUNT(local_iov), remote_iov,
                        IOVEC_COUNT(remote_iov), 0);

  if (rv < 0 || rv != (ssize_t)addrlen)
    return -1;

  *saddrlen = addrlen;

  return 0;
}

static int write_sockaddr(genlb_state_t *s, pid_t tracee,
                          struct sockaddr *saddr, socklen_t salen) {
  char *addr;
  struct iovec local_iov[1];
  struct iovec remote_iov[1];

  ssize_t rv;

  (void)s;

  errno = 0;
  addr = (char *)ptrace(PTRACE_PEEKUSER, tracee, sizeof(long) * RSI, 0);
  switch (errno) {
  case 0:
    break;
  case ESRCH:
    return 0;
  default:
    return -1;
  }

  local_iov[0].iov_base = saddr;
  local_iov[0].iov_len = salen;

  remote_iov[0].iov_base = addr;
  remote_iov[0].iov_len = salen;

  rv = process_vm_writev(tracee, local_iov, IOVEC_COUNT(local_iov), remote_iov,
                         IOVEC_COUNT(remote_iov), 0);

  if (rv < 0 || rv != (ssize_t)salen)
    return -1;

  return 0;
}

static void usage() {
  errx(EXIT_FAILURE,
       "[OPTION] <COMMAND> <ARG>...\n"
       "version: %s (using %s sandbox)\n\n"
       "-c, --connect-failure  strategy: exit, continue (default: continue)\n"
       "-v, --verbose          verbose mode\n",
       GENLB_VERSION, GENLB_SANDBOX);
}
