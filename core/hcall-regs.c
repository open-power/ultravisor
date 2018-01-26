// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright 2019 IBM Corp.  */

#include <inttypes.h>
#include <stdlib.h>
#include <hvcall.h>
#include <utils.h>
#include <stdio.h>
#include <errno.h>
#include <ccan/intmap/intmap.h>

/* prefer load/store terminology to add/get */
#define uv_intmap_load(map, index)		uintmap_get(map, index);
#define uv_intmap_store(map, index, ptr)	uintmap_add(map, index, ptr)

/*
 * Map each hcall to the number of input/output registers it uses.
 *
 * @todo: In the table below:
 * 	"not used" means we have not yet found its documentation and it
 * 		is not yet used in Linux kernel. These hcalls have a -1
 * 		for both input and output registers and get_n_hcall_regs()
 * 		for these hcalls will currently abort.
 *
 * References:
 * 	- Linux kernel v5.0-rc1
 * 	- Virtualization Linux on Power Architecture Reference Workgroup Notes
 * 	  Revision 0.5_pre4 (January 8, 2019) (from openpowerfoundation.org).
 * 	- Linux on Power Architecture Platform Reference
 * 	  Version 1.1 24 March 2016
 */
struct hcall_regs {
	uint64_t hcall;			/* hcall number */
	int16_t n_input_regs;		/* including R3 (hcall number) */
	int16_t n_output_regs;		/* including R3 (return value) */
} hcall_regs_table[] = {
	{ H_REMOVE,				6,	 3 },
	{ H_ENTER,				7,	 2 },
	{ H_READ,				3,	 9 },
	{ H_CLEAR_MOD,				3,	 2 },
	{ H_CLEAR_REF,				3,	 2 },
	{ H_PROTECT,				4,	 1 },
	{ H_GET_TCE,				3,	 2 },
	{ H_PUT_TCE,				4,	 1 },
	{ H_SET_SPRG0,				2,	 1 },
	{ H_SET_DABR,				2,	 1 },
	{ H_PAGE_INIT,				4,	 1 },
	{ H_SET_ASR,				-1,	-1 },	// not used
	{ H_ASR_ON,				-1,	-1 },	// not used
	{ H_ASR_OFF,				-1,	-1 },	// not used
	{ H_LOGICAL_CI_LOAD,			3,	 2 },
	{ H_LOGICAL_CI_STORE,			4,	 1 },
	{ H_LOGICAL_CACHE_LOAD,			-1,	-1 },	// not used
	{ H_LOGICAL_CACHE_STORE,		-1,	-1 },	// not used
	{ H_LOGICAL_ICBI,			-1,	-1 },	// not used
	{ H_LOGICAL_DCBF,			-1,	-1 },	// not used
	{ H_GET_TERM_CHAR,			2,	 4 },
	{ H_PUT_TERM_CHAR,			5,	 1 },
	{ H_REAL_TO_LOGICAL,			-1,	-1 },	// not used
	{ H_HYPERVISOR_DATA,			2,	 9 },
	{ H_EOI,				2,	 1 },
	{ H_CPPR,				2,	 1 },
	{ H_IPI,				3,	 1 },
	{ H_IPOLL,				2,	 3 },
	{ H_XIRR,				1,	 2 },
	{ H_PERFMON,				3,	 2 },
	{ H_MIGRATE_DMA,			4,	 1 },
	{ H_REGISTER_VPA,			4,	 1 },
	{ H_CEDE,				1,	 1 },
	{ H_CONFER,				3,	 1 },
	{ H_PROD,				2,	 1 },
	{ H_GET_PPP,				1,	 6 },
	{ H_SET_PPP,				3,	 1 },
	{ H_PURR,				1,	 2 },
	{ H_PIC,				4,	 1 },
	{ H_REG_CRQ,				4,	 1 },
	{ H_FREE_CRQ,				2,	 1 },
	{ H_VIO_SIGNAL,				3,	 1 },
	{ H_SEND_CRQ,				4,	 1 },
	{ H_COPY_RDMA,				6,	 9 },
	{ H_REGISTER_LOGICAL_LAN,		6,	 1 },
	{ H_FREE_LOGICAL_LAN,			2,	 1 },
	{ H_ADD_LOGICAL_LAN_BUFFER,		3,	 1 },
	{ H_SEND_LOGICAL_LAN,			9,	 1 },
	{ H_BULK_REMOVE,			9,	 2 },
	{ H_MULTICAST_CTRL,			4,	 2 },
	{ H_SET_XDABR,				3,	 1 },
	{ H_STUFF_TCE,				5,	 1 },
	{ H_PUT_TCE_INDIRECT,			5,	 1 },
	{ H_CHANGE_LOGICAL_LAN_MAC,		3,	 1 },
	{ H_VTERM_PARTNER_INFO,			5,	 1 },
	{ H_REGISTER_VTERM,			4,	 1 },
	{ H_FREE_VTERM,				2,	 1 },
	{ H_RESET_EVENTS,			-1,	-1 },	// not used
	{ H_ALLOC_RESOURCE,			-1,	-1 },	// not used
	{ H_FREE_RESOURCE,			-1,	-1 },	// not used
	{ H_MODIFY_QP,				-1,	-1 },	// not used
	{ H_QUERY_QP,				-1,	-1 },	// not used
	{ H_REREGISTER_PMR,			-1,	-1 },	// not used
	{ H_REGISTER_SMR,			-1,	-1 },	// not used
	{ H_QUERY_MR,				-1,	-1 },	// not used
	{ H_QUERY_MW,				-1,	-1 },	// not used
	{ H_QUERY_HCA,				-1,	-1 },	// not used
	{ H_QUERY_PORT,				-1,	-1 },	// not used
	{ H_MODIFY_PORT,			-1,	-1 },	// not used
	{ H_DEFINE_AQP1,			-1,	-1 },	// not used
	{ H_GET_TRACE_BUFFER,			-1,	-1 },	// not used
	{ H_DEFINE_AQP0,			-1,	-1 },	// not used
	{ H_RESIZE_MR,				-1,	-1 },	// not used
	{ H_ATTACH_MCQP,			-1,	-1 },	// not used
	{ H_DETACH_MCQP,			-1,	-1 },	// not used
	{ H_CREATE_RPT,				-1,	-1 },	// not used
	{ H_REMOVE_RPT,				-1,	-1 },	// not used
	{ H_REGISTER_RPAGES,			-1,	-1 },	// not used
	{ H_DISABLE_AND_GETC,			-1,	-1 },	// not used
	{ H_ERROR_DATA,				-1,	-1 },	// not used
	{ H_GET_HCA_INFO,			-1,	-1 },	// not used
	{ H_GET_PERF_COUNT,			-1,	-1 },	// not used
	{ H_MANAGE_TRACE,			-1,	-1 },	// not used
	{ H_GET_CPU_CHARACTERISTICS,		2,	 3 },
	{ H_FREE_LOGICAL_LAN_BUFFER,		3,	 1 },
	{ H_QUERY_INT_STATE,			-1,	-1 },	// not used
	{ H_POLL_PENDING,			1,	 1 },
	{ H_ILLAN_ATTRIBUTES,			4,	 2 },
	{ H_MODIFY_HEA_QP,			-1,	-1 },	// not used
	{ H_QUERY_HEA_QP,			-1,	-1 },	// not used
	{ H_QUERY_HEA,				-1,	-1 },	// not used
	{ H_QUERY_HEA_PORT,			-1,	-1 },	// not used
	{ H_MODIFY_HEA_PORT,			-1,	-1 },	// not used
	{ H_REG_BCMC,				-1,	-1 },	// not used
	{ H_DEREG_BCMC,				-1,	-1 },	// not used
	{ H_REGISTER_HEA_RPAGES,		-1,	-1 },	// not used
	{ H_DISABLE_AND_GET_HEA,		-1,	-1 },	// not used
	{ H_GET_HEA_INFO,			-1,	-1 },	// not used
	{ H_ALLOC_HEA_RESOURCE,			-1,	-1 },	// not used
	{ H_ADD_CONN,				-1,	-1 },	// not used
	{ H_DEL_CONN,				-1,	-1 },	// not used
	{ H_JOIN,				1,	 1 },
	{ H_VASI_STATE,				2,	 2 },
	{ H_VIOCTL,				6,	 1 },
	{ H_ENABLE_CRQ,				2,	 1 },
	{ H_GET_EM_PARMS,			1,	 7 },
	{ H_SET_MPP,				3,	 1 },
	{ H_GET_MPP,				1,	 8 },
	{ H_REG_SUB_CRQ,			4,	 3 },
	{ H_HOME_NODE_ASSOCIATIVITY,		3,	 7 },
	{ H_FREE_SUB_CRQ,			3,	 1 },
	{ H_SEND_SUB_CRQ,			7,	 1 },
	{ H_SEND_SUB_CRQ_INDIRECT,		5,	 1 },
	{ H_BEST_ENERGY,			10,	 3 },
	{ H_XIRR_X,				2,	 3 },
	{ H_RANDOM,				2,	 2 },
	{ H_COP,				8,	 1 },
	{ H_GET_MPP_X,				1,	 8 },
	{ H_SET_MODE,				5,	 1 },
	{ H_BLOCK_REMOVE,			10,	 1 },
	{ H_CLEAR_HPT,				1,	 1 },
	{ H_REQUEST_VMC,			-1,	-1 },	// not used
	{ H_RESIZE_HPT_PREPARE,			3,	 1 },
	{ H_RESIZE_HPT_COMMIT,			3,	 1 },
	{ H_REGISTER_PROC_TBL,			5,	 1 },
	{ H_SIGNAL_SYS_RESET,			2,	 1 },
	{ H_INT_GET_SOURCE_INFO,		3,	 5 },
	{ H_INT_SET_SOURCE_CONFIG,		6,	 1 },
	{ H_INT_GET_SOURCE_CONFIG,		-1,	-1 },	// not used
	{ H_INT_GET_QUEUE_INFO,			4,	 3 },
	{ H_INT_SET_QUEUE_CONFIG,		6,	 1 },
	{ H_INT_GET_QUEUE_CONFIG,		-1,	-1 },	// not used
	{ H_INT_SET_OS_REPORTING_LINE,		-1,	-1 },	// not used
	{ H_INT_GET_OS_REPORTING_LINE,		-1,	-1 },	// not used
	{ H_INT_ESB,				5,	 2 },
	{ H_INT_SYNC,				3,	 1 },
	{ H_INT_RESET,				2,	 1 },
	{ H_SCM_READ_METADATA,			4,	 2 },
	{ H_SCM_WRITE_METADATA,			5,	 1 },
	{ H_SCM_BIND_MEM,			6,	 2 },
	{ H_SCM_UNBIND_MEM,			5,	 2 },
	{ H_SCM_QUERY_BLOCK_MEM_BINDING,	-1,	-1 },	// not used
	{ H_SCM_QUERY_LOGICAL_MEM_BINDING,	-1,	-1 },	// not used
	{ H_SCM_MEM_QUERY,			-1,	-1 },	// not used
	{ H_SCM_BLOCK_CLEAR,			-1,	-1 },	// not used
	{ H_SVM_PAGE_IN,			4,	 1 },
	{ H_SVM_PAGE_OUT,			4,	 1 },
	{ H_SVM_INIT_START,			1,	 1 },
	{ H_SVM_INIT_DONE,			1,	 1 },
	{ H_RTAS,				2,	 2 },
	{ H_GET_24X7_CATALOG_PAGE,		4,	 1 },
	{ H_GET_24X7_DATA,			5,	 1 },
	{ H_GET_PERF_COUNTER_INFO,		3,	 1 },
	{ H_SET_PARTITION_TABLE,		2,	 1 },
	{ H_ENTER_NESTED,			3,	 1 },
	{ H_TLB_INVALIDATE,			4,	 1 },
	{ H_COPY_TOFROM_GUEST,			7,	 1 },
};

typedef UINTMAP(struct hcall_regs *) hcall_regs_map_t;

static hcall_regs_map_t hcall_regs_map;

/*
 * As mentioned above, hcall_regs_table maps an hcall number to the number
 * of input/output registers for the hcall. But since hcall numbers are
 * not contigous we cannot just index into the table and a linear search
 * would of course be inefficient.
 *
 * Create an 'intmap' object to map the hcall number to its entry in the
 * hcall_regs_table and use the intmap to to quickly retrieve the hcall's
 * table entry.
 *
 * This init function must be called _only_ once!
 */
void init_hcall_regs_map(void)
{
	int i, n;
	char msg[256];
	struct hcall_regs *entry;

	uintmap_init(&hcall_regs_map);

	n = sizeof(hcall_regs_table) / sizeof(struct hcall_regs);

	for (i = 0; i < n; i++) {
		entry = &hcall_regs_table[i];

		if (!uv_intmap_store(&hcall_regs_map, entry->hcall, entry))
			goto out;
	}

	return;
out:
	snprintf(msg, sizeof(msg), "hcall_regs[]: error %d adding hcall 0x%llx",
			errno, entry->hcall);
	_abort(msg);
}

void get_n_hcall_regs(uint64_t hcall, int16_t *n_input, int16_t *n_output)
{
	char msg[256];
	struct hcall_regs *entry;

	entry = uv_intmap_load(&hcall_regs_map, hcall);

	if (entry) {
		*n_input = entry->n_input_regs;
		*n_output = entry->n_output_regs;

		if (*n_input > 0 && *n_output > 0)
			return;
	}

	snprintf(msg, sizeof(msg), "HCALL 0X%llX not supported!", hcall);
	_abort(msg);
}
