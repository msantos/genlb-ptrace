.PHONY: all clean test

CFLAGS ?= -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong \
					-Wformat -Werror=format-security \
					-pie -fPIE \
					-fno-strict-aliasing
LDFLAGS ?= -Wl,-z,relro,-z,now -Wl,-z,noexecstack

RESTRICT_PROCESS ?= null

all:
	$(CC) $(CFLAGS) -DRESTRICT_PROCESS_$(RESTRICT_PROCESS) \
		-g -Wall -Wextra -pedantic \
		-Wconversion -Wshadow \
		-Wpointer-arith -Wcast-qual \
		-Wstrict-prototypes -Wmissing-prototypes \
		-o genlb genlb.c restrict_process_null.c restrict_process_seccomp.c \
		$(LDFLAGS)

clean:
	-@rm genlb

test:
	-@PATH=.:$$PATH bats test
