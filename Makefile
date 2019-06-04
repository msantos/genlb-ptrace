CFLAGS ?= -D_FORTIFY_SOURCE=2 -O2 -fstack-protector-strong \
					-Wformat -Werror=format-security \
					-pie -fPIE \
					-fno-strict-aliasing
LDFLAGS ?= -Wl,-z,relro,-z,now -Wl,-z,noexecstack

SANDBOX ?= null

all:
	$(CC) $(CFLAGS) -DSANDBOX_$(SANDBOX) \
		-g -Wall -Wextra -pedantic \
		-Wconversion -Wshadow \
		-Wpointer-arith -Wcast-qual \
		-Wstrict-prototypes -Wmissing-prototypes \
		-o genlb genlb.c sandbox_null.c \
		$(LDFLAGS)

clean:
	-@rm genlb
