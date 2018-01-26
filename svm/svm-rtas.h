/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SVM RTAS
 *
 * Copyright 2018, IBM Corporation.
 *
 */

#ifndef SVM_RTAS_H
#define SVM_RTAS_H

#include <svm_host.h>
#include <compiler.h>

extern void svm_init_rtas(struct refl_state *r_state, gpa_t gpfdt);
extern int svm_rtas(struct refl_state *r_state);
extern int svm_rtas_return(struct refl_state *r_state);
extern void svm_cleanup_cookie(struct svm *svm);
extern void __noreturn svm_initiate_kill(struct refl_state *r, const char *m);
extern void svm_fixup_rtas_area(u64 rtas_area, struct refl_state *r_state);

#define RTAS_LOG_VERSION_6	0x06

/*
 * RTAS error log as per PAPR.
 * Copied from Linux source arch/powerpc/include/asm/rtas.h
 */
struct rtas_error_log {
	/* Byte 0 */
	uint8_t		byte0;			/* Architectural version */

	/* Byte 1 */
	uint8_t		byte1;
	/* XXXXXXXX
	 * XXX		3: Severity level of error
	 *    XX	2: Degree of recovery
	 *      X	1: Extended log present?
	 *       XX	2: Reserved
	 */

	/* Byte 2 */
	uint8_t		byte2;
	/* XXXXXXXX
	 * XXXX		4: Initiator of event
	 *     XXXX	4: Target of failed operation
	 */
	uint8_t		byte3;			/* General event or error*/
	__be32		extended_log_length;	/* length in bytes */
	unsigned char	buffer[1];		/* Start of extended log */
						/* Variable length.      */
};

static inline uint8_t rtas_error_extended(const struct rtas_error_log *elog)
{
	return (elog->byte1 & 0x04) >> 2;
}

#define RTAS_V6EXT_LOG_FORMAT_EVENT_LOG	14

#define RTAS_V6EXT_COMPANY_ID_IBM	(('I' << 24) | ('B' << 16) | ('M' << 8))

/*
 * RTAS general extended event log, Version 6. The extended log starts
 * from "buffer" field of struct rtas_error_log defined above.
 */
struct rtas_ext_event_log_v6 {
	/* Byte 0 */
	uint8_t byte0;
	/* XXXXXXXX
	 * X		1: Log valid
	 *  X		1: Unrecoverable error
	 *   X		1: Recoverable (correctable or successfully retried)
	 *    X		1: Bypassed unrecoverable error (degraded operation)
	 *     X	1: Predictive error
	 *      X	1: "New" log (always 1 for data returned from RTAS)
	 *       X	1: Big Endian
	 *        X	1: Reserved
	 */

	/* Byte 1 */
	uint8_t byte1;			/* reserved */

	/* Byte 2 */
	uint8_t byte2;
	/* XXXXXXXX
	 * X		1: Set to 1 (indicating log is in PowerPC format)
	 *  XXX		3: Reserved
	 *     XXXX	4: Log format used for bytes 12-2047
	 */

	/* Byte 3 */
	uint8_t byte3;			/* reserved */
	/* Byte 4-11 */
	uint8_t reserved[8];		/* reserved */
	/* Byte 12-15 */
	__be32  company_id;		/* Company ID of the company	*/
					/* that defines the format for	*/
					/* the vendor specific log type	*/
	/* Byte 16-end of log */
	uint8_t vendor_log[1];		/* Start of vendor specific log	*/
					/* Variable length.		*/
} __packed;

static inline
uint8_t rtas_ext_event_log_format(struct rtas_ext_event_log_v6 *ext_log)
{
	return ext_log->byte2 & 0x0F;
}

/* pSeries event log format */

/* Two bytes ASCII section IDs */
#define PSERIES_ELOG_SECT_ID_MCE		(('M' << 8) | 'C')

/* Vendor specific Platform Event Log Format, Version 6, section header */
struct pseries_errorlog {
	__be16 id;			/* 0x00 2-byte ASCII section ID	*/
	__be16 length;			/* 0x02 Section length in bytes	*/
	uint8_t version;		/* 0x04 Section version		*/
	uint8_t subtype;		/* 0x05 Section subtype		*/
	__be16 creator_component;	/* 0x06 Creator component ID	*/
	uint8_t data[];			/* 0x08 Start of section data	*/
};

/*
 * RTAS pseries MCE errorlog section.
 * Copied from Linux source arch/powerpc/platforms/pseries/ras.c
 */
struct pseries_mc_errorlog {
	__be32	fru_id;
	__be32	proc_id;
	u8	error_type;
	/*
	 * sub_err_type (1 byte). Bit fields depends on error_type
	 *
	 *   MSB0
	 *   |
	 *   V
	 *   01234567
	 *   XXXXXXXX
	 *
	 * For error_type == MC_ERROR_TYPE_UE
	 *   XXXXXXXX
	 *   X		1: Permanent or Transient UE.
	 *    X		1: Effective address provided.
	 *     X	1: Logical address provided.
	 *      XX	2: Reserved.
	 *        XXX	3: Type of UE error.
	 *
	 * For error_type != MC_ERROR_TYPE_UE
	 *   XXXXXXXX
	 *   X		1: Effective address provided.
	 *    XXXXX	5: Reserved.
	 *         XX	2: Type of SLB/ERAT/TLB error.
	 */
	u8	sub_err_type;
	u8	reserved_1[6];
	__be64	effective_address;
	__be64	logical_address;
} __packed;

/* RTAS pseries MCE error types */
#define MC_ERROR_TYPE_UE		0x00
#define MC_ERROR_TYPE_SLB		0x01
#define MC_ERROR_TYPE_ERAT		0x02
#define MC_ERROR_TYPE_UNKNOWN		0x03
#define MC_ERROR_TYPE_TLB		0x04

/*
 * Per PAPR,
 * For UE error type, bit 1 of sub_err_type indicates whether effective addr
 * is provided or not. For other error types (SLB/ERAT/TLB), bit 0 indicates
 * same.
 */
#define MC_UE_EA_ADDR_PROVIDED		0x40
#define MC_EA_ADDR_PROVIDED		0x80

#define RTAS_ERROR_LOG_MAX		2048

#define SRR1_MC_LOADSTORE(srr1)		((srr1) & PPC_BIT(42))

static inline
void rtas_mc_set_effective_addr(struct pseries_mc_errorlog *mlog, u64 ea)
{
	switch (mlog->error_type) {
	case	MC_ERROR_TYPE_UE:
		if (mlog->sub_err_type & MC_UE_EA_ADDR_PROVIDED)
			mlog->effective_address = ea;
		break;
	case	MC_ERROR_TYPE_SLB:
	case	MC_ERROR_TYPE_ERAT:
	case	MC_ERROR_TYPE_TLB:
		if (mlog->sub_err_type & MC_EA_ADDR_PROVIDED)
			mlog->effective_address = ea;
		break;
	default:
		break;
	}
	return;
}

#endif /* SVM_RTAS_H */

