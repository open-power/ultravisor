# -*-Makefile-*-

SUBDIRS += core
CORE_OBJS = bitmap.o chip.o console.o console-log.o cpu.o context.o device.o
CORE_OBJS += exceptions.o hvcall.o init.o lock.o malloc.o mem_region.o
CORE_OBJS += page_alloc.o pgtable.o relocate.o stack.o svm_host.o timebase.o
CORE_OBJS += urmor.o utils.o xscom.o uvcall.o tlbflush.o mmio.o
CORE_OBJS += hcall-regs.o page_encrypt.o cookies.o numa.o numa_fault.o
CORE_OBJS += pagein_track.o

CORE=core/built-in.a

$(CORE): $(CORE_OBJS:%=core/%)
