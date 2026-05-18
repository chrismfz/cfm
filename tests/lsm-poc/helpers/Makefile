# Build the C helpers each scenario shells out to.
#
# Plain C99, no kernel headers required (the bpf-mapcreate helper uses
# raw syscall numbers and a minimal struct definition rather than
# pulling in libbpf or linux/bpf.h, so the harness works on any host
# with gcc).

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu99
BINDIR   = bin

HELPERS = \
	$(BINDIR)/memfd-exec \
	$(BINDIR)/deleted-exec \
	$(BINDIR)/fdleak-attacker \
	$(BINDIR)/bpf-mapcreate \
	$(BINDIR)/suid-dropper \
	$(BINDIR)/interp-stdio-helper \
	$(BINDIR)/setcapper \
	$(BINDIR)/kmod-loader \
	$(BINDIR)/knob-writer \
	$(BINDIR)/kexec-loader \
	$(BINDIR)/ptracer

.PHONY: all clean
all: $(BINDIR) $(HELPERS)

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/%: %.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BINDIR)
