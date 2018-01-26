
CC = /opt/at11.0/bin/gcc
#
# Build statically so we can run in a buildroot environment
CFLAGS = -static

BINS = test1-altivec test1-vsx test2-altivec test2-vsx

all: $(BINS) check

test1-altivec:test1.c
	$(CC) $(CFLAGS) -o test1-altivec -maltivec=le -mno-vsx test1.c

test1-vsx:test1.c
	$(CC) $(CFLAGS) -o test1-vsx -mvsx test1.c

test2-altivec:test2.c
	$(CC) $(CFLAGS) -o test2-altivec -maltivec=le -mno-vsx test2.c

test2-vsx:test2.c
	$(CC) $(CFLAGS) -o test2-vsx -mvsx test2.c

# Check generated code for Altivec (lvx/stvx) and VSX (lxvd2x/stxvd2x)
# instructions. If the instructions are not found, fail the make.
#
# @todo: Be smarter/less verbose.
#
check: $(BINS)
	objdump -D test1-altivec > test1-altivec.od
	grep -q lvx test1-altivec.od
	objdump -D test1-vsx > test1-vsx.od
	grep -q lxvd2x test1-vsx.od
	objdump -D test2-altivec > test2-altivec.od
	grep -q lvx test2-altivec.od
	objdump -D test2-vsx > test2-vsx.od
	grep -q lxvd2x test2-vsx.od

clean:
	rm -f *-altivec *.od *-vsx
