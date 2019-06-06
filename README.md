genlb - connection load balancer for Unix processes

# SYNOPSIS

genlb [-c *strategy*|-v] *command* *arg* *...*

# DESCRIPTION

`genlb` monitors a subprocess, intercepting calls to `connect(2)` using
`ptrace(2)`.

If the destination of the `connect(2)` matches an IP address/port,
`genlb` probes a list of IP addresses and rewrites the `connect(2)`
in the subprocess to use the first working IP.

`genlb` uses the [libglb](https://github.com/msantos/genlb) `LD_PRELOAD`
library for the `connect(2)` load balancing.

# EXAMPLES

    ## Create 2 test listeners

    # shell 1
    nc -vvv -k -l 127.3.0.1 8000

    # shell 2
    nc -vvv -k -l 127.3.0.2 8000

    ## Load balanced client
    LD_PRELOAD=libglb.so \
    GLB_OPTIONS="--random 127.0.0.1:8000 127.3.0.1 127.3.0.2" \
    genlb nc -vvv 127.0.0.1 8000

# ENVIRONMENT VARIABLES

LD\_PRELOAD=libglb.so
: Set path to libglb

GLB\_OPTIONS
: See https://github.com/msantos/genlb/blob/master/README.md

# OPTIONS

-c, --connect-failure *exit*|*continue*
: Behaviour on `connect(2)` failure

-v, --verbose
:	Enable debug messages

# BUILDING

## Quick Install

    make

# SEE ALSO

* [glb upstream](https://github.com/codership/glb)

* [Modifying System Call Arguments With ptrace](http://www.alfonsobeato.net/c/modifying-system-call-arguments-with-ptrace/)

* [Filter and Modify System Calls with seccomp and ptrace](https://www.alfonsobeato.net/c/filter-and-modify-system-calls-with-seccomp-and-ptrace/)
