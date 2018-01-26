# -*-Makefile-*-

SUBDIRS += ccan ccan/list ccan/str ccan/bitops ccan/intmap ccan/tcon
CCAN_OBJS = list/list.o str/str.o bitops/bitops.o intmap/intmap.o
CCAN=ccan/built-in.a

$(CCAN): $(CCAN_OBJS:%=ccan/%)

