# -*-Makefile-*-

UV_DIR = uv

SUBDIRS += $(UV_DIR)

UV_SRCS = uv-crypto.c uv-xscom-bwlist.c tssdevuv.c tssuv.c
UV_OBJS = $(UV_SRCS:%.c=%.o)

# TSS configuration flags for tssdevuv.c and tssuv.c
CFLAGS_uv/ = -DTPM_POSIX -DTPM_TPM20 -DTPM_NOSOCKET -DTPM_NODEV
CFLAGS_uv/ += -DTPM_TSS_NOECC -DTPM_TSS_NORSA -D__ULTRAVISOR__
CFLAGS_uv/ += -DTPM_TSS_NOFILE -DTPM_TSS_NOENV -DTPM_TSS_NOSCAN
CFLAGS_uv/ += -DALG_SHA1=NO

UV = $(UV_DIR)/built-in.a

$(UV): $(UV_OBJS:%=$(UV_DIR)/%)
