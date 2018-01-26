SUBDIRS += $(PLATDIR)/p9

P9_OBJS = sbe-p9.o
P9 = $(PLATDIR)/p9/built-in.a
$(P9): $(P9_OBJS:%=$(PLATDIR)/p9/%)

