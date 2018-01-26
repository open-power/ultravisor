# -*-Makefile-*-

SUBDIRS += tss

CPPFLAGS += -I$(SRC)/tss

TSS_SRCS = tss.c tss20.c tssauth.c tssauth20.c tssccattributes.c
TSS_SRCS += tsscryptoh.c tsscryptombed.c tsscryptouv.c
TSS_SRCS += tssmarshal.c tssprint.c tssprintcmd.c tssproperties.c
TSS_SRCS += tssresponsecode.c tsstransmit.c tssutils.c tssntc.c
TSS_SRCS += Commands.c CommandAttributeData.c Unmarshal.c

TSS_OBJS = $(TSS_SRCS:%.c=%.o)

CFLAGS_tss/ = -DTPM_POSIX -DTPM_TPM20 -DTPM_NOSOCKET -DTPM_NODEV
CFLAGS_tss/ += -DTPM_TSS_NOECC -DTPM_TSS_NORSA -D__ULTRAVISOR__
CFLAGS_tss/ += -DTPM_TSS_NOFILE -DTPM_TSS_NOENV -DTPM_TSS_NOSCAN
CFLAGS_tss/ += -DALG_SHA1=NO

TSS = tss/built-in.a

$(TSS): $(TSS_OBJS:%=tss/%)
