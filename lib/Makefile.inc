# -*-Makefile-*-

SUBDIRS += lib
LIB_OBJS = instr.o

LIB=lib/built-in.a

$(LIB): $(LIB_OBJS:%=lib/%)
