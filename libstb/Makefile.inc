# -*-Makefile-*-

LIBSTB_DIR = libstb

SUBDIRS += $(LIBSTB_DIR)

libstb/create-container: libstb/create-container.c libstb/container-utils.c
	$(call Q, HOSTCC ,$(HOSTCC) $(HOSTCFLAGS) \
	-Wpadded -O0 -g -I$(SRC) -I$(SRC)/include -o $@ $^ -lssl -lcrypto,$<)

libstb/print-container: libstb/print-container.c libstb/container-utils.c
	$(call Q, HOSTCC , $(HOSTCC) $(HOSTCFLAGS) \
	-O0 -g -I$(SRC) -I$(SRC)/include -o $@ $^ -lssl -lcrypto, $<)

clean: create-container-clean

create-container-clean:
	$(RM) libstb/create-container libstb/print-container
