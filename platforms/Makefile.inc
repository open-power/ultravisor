PLATDIR = platforms

SUBDIRS += $(PLATDIR)
PLATFORMS = $(PLATDIR)/built-in.a

include $(SRC)/$(PLATDIR)/mambo/Makefile.inc
include $(SRC)/$(PLATDIR)/p9/Makefile.inc

$(PLATFORMS): $(MAMBO) $(P9)
