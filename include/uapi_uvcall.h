/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Ultravisor calls.
 *
 * Copyright 2018, IBM Corporation.
 *
 */
#ifndef UAPI_UC_H
#define UAPI_UC_H

#define UV_WRITE_PATE		0xF104
#define UV_RESTRICTED_SPR_WRITE	0xF108
#define UV_RESTRICTED_SPR_READ	0xF10C
#define UV_ESM			0xF110
#define UV_READ_SCOM		0xF114
#define UV_WRITE_SCOM		0xF118
#define UV_RETURN		0xF11C
#define UV_REGISTER_MEM_SLOT	0xF120
#define UV_UNREGISTER_MEM_SLOT	0xF124
#define UV_PAGE_IN		0xF128
#define UV_PAGE_OUT		0xF12C
#define UV_SHARE_PAGE		0xF130
#define UV_UNSHARE_PAGE         0xF134
#define UV_PAGE_INVAL           0xF138
#define UV_SVM_TERMINATE	0xF13C
#define UV_UNSHARE_ALL_PAGES	0xF140
#define UV_READ_MEM		0xF144
#define UV_WRITE_MEM		0xF148
#define UV_ESMB_GET_FILE	0xF14C
#define UV_SEND_SBE_COMMAND	0xF150

/*
 * @todo: create 2 UV calls (UV_GET and UV_SET) to interact with the Ultravisor
 * configuration and retrieve various statistics.
 *
 * Interesting items to read using UV_GET could be:
 * - Amount of configured and free secure memory (global and per node)
 * - List of SVM (LPID)
 * - Per SVM Size of secure memory
 * - Per SVM Number of shared pages
 * - Per SVM Amount of distant page fault
 * - Per SVM Amount of migrated pages
 * - Per SVM Current main node
 *
 * Interesting items to write UV_SET could be:
 * - Global logging level
 * - Per SVM Switching page migration on or off (when implemented)
 *
 * Access should be control this way:
 * - Write access only from the Hypervisor kernel (MSR[S,HV,PR] == 0,1,0)
 * - Read access only from Hypervisor kernel context (MSR[S,HV,PR] == 0,1,1)
 */


#define SPRN_DAWR       0xB4
#define SPRN_DAWRX      0xBC
#define SPRN_CIABR      0xBB
#define SPRN_LDBAR      0x352
#define SPRN_IMC        0x31F

/* ERROR VALUES */
/**
 * @todo: Synchronize the error codes below with the HV error codes?
 * 	  The "external" error codes in HV are based on LoPAPR while
 * 	  internal error codes are based on KVM. The Ultravisor error
 * 	  codes here and in include/uvcall.h are a mix of the two. In
 * 	  addition, the UV has some unique error codes which overlap
 * 	  with other HV error codes. eg:
 *
 * 	  	U_XSCOM_PARTIAL_GOOD	-25
 * 	  	U_XSCOM_CLOCK_ERROR	-26
 *
 * 	  	H_TOKEN_PARM    -25
 *		H_MLENGTH_PARM  -27
 *
 *	  From an API perspective though, HV and SVM must use the UV_
 *	  macros like U_SUCCESS or U_FUNCTION and not rely on specific
 *	  error codes.
 */
#define U_SUCCESS 	0
#define U_FUNCTION	-2  /* Function not supported */
#define U_PARAMETER	-4  /* Parameter invalid, out-of-range or conflicting */
#define U_RETRY		-5  /* No resources */
#define U_PERMISSION	-11
#define U_P2		-55
#define U_P3		-56
#define U_P4		-57
#define U_P5		-58
#define U_BAD_MODE	-59	/* Illegal msr value */
#define U_STATE		-75 /* Invalid State */

#endif /* #ifndef UAPI_UC_H */
