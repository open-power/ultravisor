// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 IBM Corp.
 */

#undef DEBUG
#define pr_fmt(fmt) "SVM-RTAS-HDLR: " fmt

#include <compiler.h>
#include <context.h>
#include <errno.h>
#include <exceptions.h>
#include <inttypes.h>
#include <logging.h>
#include <stack.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <svm/svm-internal.h>
#include <svm/svm-rtas-bbuf.h>
#include <svm/svm-rtas-hdlr.h>
#include <unistd.h>
#include <utils.h>

//#define DEBUG
#ifdef DEBUG
#define svm_rtas_dprintf(fmt...)		\
	do {					\
		printf(fmt);			\
	} while (0)
#else
#define svm_rtas_dprintf(fmt...)		\
	do {					\
	} while (0)
#endif

static size_t _svm_rtas_get_sys_param_len(struct mm_struct *mm, gpa_t buf)
{
	hpa_t buf_hpa;
	uint8_t *sys_param;
	size_t length;

	buf_hpa = (hpa_t)gpa_to_addr(mm, buf, NULL);
	if (!buf_hpa)
		return -1;

	sys_param = (uint8_t *)buf_hpa;
	length = ((sys_param[0] << 8) | sys_param[1]);
	svm_rtas_dprintf("%s: length 0x%lx\n", __func__, length);

	return length;
}

/**
 * @brief snprintf to bounce buffer.
 *
 * @param r_state Contains rstate pointer.
 * @param bbuf Page aligned buffer to copy to.
 * @param buf_from Guest gpa to print from.
 */

static ssize_t _svm_rtas_snprintf_bbuf(struct mm_struct *mm, gpa_t bbuf,
				       gpa_t buf_from)
{
	hpa_t bbuf_hpa;
	hpa_t buf_from_hpa;
	ssize_t length;

	bbuf_hpa = (hpa_t)gpa_to_addr(mm, bbuf, NULL);
	assert(bbuf_hpa);
	buf_from_hpa = (hpa_t)gpa_to_addr(mm, buf_from, NULL);
	assert(buf_from_hpa);

	length = snprintf((char *)bbuf_hpa, RTAS_BUF_BBUF_SZ, "%s",
			  (char *)buf_from_hpa);

	if (length < 0)
		pr_error("%s: length [%ld]\n", __func__, length);

	return length;
}

/*
 *   - Token for check-exception
 *   - nargs 6 / 7 (with Extended Information)
 *   - nret 1
 *   - args[0] = Vector Offset
 *   - args[1] = Additional Information
 *   - args[2] = Event Mask
 *   - args[3] = Critical
 *   - args[4] = Buffer - Real address of error log
 *   - args[5] = Length - Length of error log buffer.
 *   - args[6] = Extended Information
 *   - ret = args[6 / 7] = Status
 *
 */
static enum rtas_hdlr_ret
svm_rtas_chk_excp_hdlr(enum rtas_hdlr_type type,
		       struct svm *svm,
		       struct rtas_args *guest_args,
		       struct rtas_args *bb_args)
{
	enum rtas_hdlr_ret ret = RTAS_HDLR_OK;

	if (type == RTAS_HDLR_PRE) {
		svm_rtas_dprintf("[PRE] chk_excp token 0x%x\n", bb_args->token);

		if (bb_args->args[5] > RTAS_BUF_BBUF_SZ)
			return RTAS_HDLR_ERR;

		/* Set error log address to address of bounce buffer. */
		bb_args->args[4] = svm_rtas_bbuf_alloc(&svm->mm, &svm->rtas);
		if (!bb_args->args[4])
			return RTAS_HDLR_ERR;
	} else {
		/* check-exception Status in args[4] */
		int status;

		if (guest_args->nargs == 6)
			status = guest_args->args[6];
		else
			status = guest_args->args[7];

		svm_rtas_dprintf("[POST] chk_excp token 0x%x"
				 " status [%d]\n",
				 guest_args->token, status);

		/*
		 * check-exception status:
		 *  1: No Errors Found
		 *  0: New Error Log returned
		 * -1: Hardware Error
		 */
		if (status == 0 &&
		    svm_rtas_bbuf_memcpy(&svm->mm,
				guest_args->args[4],
				bb_args->args[4],
				guest_args->args[5]) != guest_args->args[5])
			ret = RTAS_HDLR_ERR;

		svm_rtas_bbuf_free(&svm->rtas, bb_args->args[4]);
	}

	return ret;
}

/*
 *   - Token for event-scan
 *   - nargs 4
 *   - nret 1
 *   - args[0] = event mask
 *   - args[1] = Critical
 *   - args[2] = Buffer - Real address of error log.
 *   - args[3] = Length - Length of error log buffer.
 *   - ret = args[4] = Status
 */
static enum rtas_hdlr_ret
svm_rtas_event_scan_hdlr(enum rtas_hdlr_type type,
			 struct svm *svm,
			 struct rtas_args *guest_args,
			 struct rtas_args *bb_args)
{
	enum rtas_hdlr_ret ret = RTAS_HDLR_OK;

	if (type == RTAS_HDLR_PRE) {
		svm_rtas_dprintf("[PRE] event_scan token 0x%x\n",
				 bb_args->token);

		if (bb_args->args[3] > RTAS_BUF_BBUF_SZ)
			return RTAS_HDLR_ERR;

		/* Set error log address to address of bounce buffer. */
		bb_args->args[2] = svm_rtas_bbuf_alloc(&svm->mm, &svm->rtas);
		if (!bb_args->args[2])
			return RTAS_HDLR_ERR;
	} else {
		/* event-scan Status in args[4] */
		int status = guest_args->args[4];

		svm_rtas_dprintf("[POST] event_scan token 0x%x"
				 " status [%d]\n",
				 guest_args->token, status);

		/*
		 * event-scan status:
		 *  1: No Errors Found
		 *  0: New Error Log returned
		 * -1: Hardware Error
		 */
		if (status == 0 &&
		    svm_rtas_bbuf_memcpy(&svm->mm,
				guest_args->args[2],
				bb_args->args[2],
				guest_args->args[3]) != guest_args->args[3])
			ret = RTAS_HDLR_ERR;

		svm_rtas_bbuf_free(&svm->rtas, bb_args->args[2]);
	}

	return ret;
}

#define CALL_AGAIN	-2

/*
 *   - Token for ibm,configure-connector
 *   - nargs 2
 *   - nret 1
 *   - args[0] = Work area - Address of work area
 *   - args[1] = Memory extent - 0 or address of additional
 *   - ret = args[2] = Status
 *
 */
static enum rtas_hdlr_ret svm_rtas_ibm_cfg_conn_hdlr(enum rtas_hdlr_type type,
						struct svm *svm,
						struct rtas_args *guest_args,
						struct rtas_args *bb_args)
{
	enum rtas_hdlr_ret ret = RTAS_HDLR_OK;

	if (type == RTAS_HDLR_PRE) {
		svm_rtas_dprintf("[PRE] ibm_cfg_conn token 0x%x\n",
				 bb_args->token);

		if (bb_args->args[1]) {
			pr_error("%s: Additional work area memory not supported [%x]\n",
				 __func__, guest_args->args[1]);
			return RTAS_HDLR_ERR;
		}

		/* Set Work area to address of bounce buffer. */
		bb_args->args[0] = svm_rtas_bbuf_alloc(&svm->mm, &svm->rtas);
		if (!bb_args->args[0])
			return RTAS_HDLR_ERR;

		if (svm_rtas_bbuf_memcpy(&svm->mm,
				         bb_args->args[0],
				         guest_args->args[0],
					 4096) != 4096) {
			svm_rtas_bbuf_free(&svm->rtas, bb_args->args[0]);
			bb_args->args[0] = 0;
			return RTAS_HDLR_ERR;
		}
	} else {
		int status = guest_args->args[2];

		svm_rtas_dprintf("[POST] ibm_cfg_conn token 0x%x"
				 " status [%d]\n",
				 guest_args->token, status);

		/*
		 * CALL_AGAIN is the only negative result that
		 * ibm,configure-connector returns which isn't an error.
		 */
		if ((status >= 0 || status == CALL_AGAIN) &&
		    svm_rtas_bbuf_memcpy(&svm->mm,
					 guest_args->args[0],
					 bb_args->args[0], 4096) != 4096)
			ret = RTAS_HDLR_ERR;

		svm_rtas_bbuf_free(&svm->rtas, bb_args->args[0]);
	}
	return ret;
}

/*
 *   - Token for ibm,get-system-parameter
 *   - nargs 3
 *   - nret 1
 *   - args[0] = Token of system parameter to retrieve
 *   - args[1] = Real address of data buffer
 *   - args[2] = length of data buffer
 *   - ret = args[3] = Status
 *
 */
static enum rtas_hdlr_ret
svm_rtas_ibm_get_sys_param_hdlr(enum rtas_hdlr_type type,
				struct svm *svm,
				struct rtas_args *guest_args,
				struct rtas_args *bb_args)
{
	enum rtas_hdlr_ret ret = RTAS_HDLR_OK;

	if (type == RTAS_HDLR_PRE) {
		svm_rtas_dprintf("[PRE] ibm_get_sys_param token 0x%x\n",
				 bb_args->token);

		svm_rtas_dprintf("%s: system token: %d\n", __func__,
				 bb_args->args[0]);

		/* Verify get_sys_param length */
		if (bb_args->args[2] > RTAS_BUF_BBUF_SZ)
			return RTAS_HDLR_ERR;

		/* Set get_sys_param buf address to address of bounce buf. */
		bb_args->args[1] = svm_rtas_bbuf_alloc(&svm->mm, &svm->rtas);
		if (!bb_args->args[1])
			return RTAS_HDLR_ERR;
	} else {
		/* ibm,get-system-parameter Status in args[3] */
		int status = guest_args->args[3];
		size_t length;

		svm_rtas_dprintf("[POST] ibm_get_sys_param token 0x%x"
				 " status [%d]\n",
				 guest_args->token, status);

		if (status)
			goto free_exit;

		length = _svm_rtas_get_sys_param_len(&svm->mm,
						     bb_args->args[1]);
		if (length == -1) {
			ret = RTAS_HDLR_ERR;
			goto free_exit;
		}

		length = (length < (guest_args->args[2]) ?
			  length : guest_args->args[2]);

		if (svm_rtas_bbuf_memcpy(&svm->mm,
					 guest_args->args[1],
					 bb_args->args[1],
					 length) != length)
			ret = RTAS_HDLR_ERR;

	free_exit:
		svm_rtas_bbuf_free(&svm->rtas, bb_args->args[1]);
	}

	return ret;
}

/*
 *   - Token for ibm,os-term
 *   - nargs 1
 *   - nret 1
 *   - args[0] = Pointer to String NULL terminated string
 *   - ret = args[1] = Status
 *
 */
static enum rtas_hdlr_ret
svm_rtas_ibm_os_term_hdlr(enum rtas_hdlr_type type,
			  struct svm *svm,
			  struct rtas_args *guest_args,
			  struct rtas_args *bb_args)
{
	if (type == RTAS_HDLR_PRE) {
		ssize_t length;

		svm_rtas_dprintf("[PRE] ibm_os_term token 0x%x\n",
				 bb_args->token);

		/* Set string pointer to address of bounce buf. */
		bb_args->args[0] = svm_rtas_bbuf_alloc(&svm->mm, &svm->rtas);

		if (!bb_args->args[0])
			return RTAS_HDLR_ERR;

		length = _svm_rtas_snprintf_bbuf(&svm->mm,
						 bb_args->args[0],
						 guest_args->args[0]);

		if (length < 0) {
			pr_error("%s: snprintf_bbuf failed [%ld]\n", __func__,
				 length);
			svm_rtas_bbuf_free(&svm->rtas, bb_args->args[0]);
			bb_args->args[0] = 0;
			return RTAS_HDLR_ERR;
		}
	} else {
		svm_rtas_dprintf("[POST] ibm_os_term token 0x%x"
				 " status [%d]\n",
				 guest_args->token, guest_args->args[1]);

		svm_rtas_bbuf_free(&svm->rtas, bb_args->args[0]);
	}
	return RTAS_HDLR_OK;
}

/*
 *   - Token for ibm,set-system-parameter
 *   - nargs 2
 *   - nret 1
 *   - args[0] = Token number of the target system parameter
 *   - args[1] = Real address of data buffer
 *   - ret = args[2] = Status
 *
 */
static enum rtas_hdlr_ret
svm_rtas_ibm_set_sys_param_hdlr(enum rtas_hdlr_type type,
				struct svm *svm,
				struct rtas_args *guest_args,
				struct rtas_args *bb_args)
{
	if (type == RTAS_HDLR_PRE) {
		size_t length;

		svm_rtas_dprintf("%s: [PRE] ibm_set_sys_param token 0x%x\n",
				 __func__, bb_args->token);

		length = _svm_rtas_get_sys_param_len(&svm->mm,
						     bb_args->args[1]);

		if (length == -1 || length > RTAS_BUF_BBUF_SZ)
			return RTAS_HDLR_ERR;

		/* Set ibm,set-system-parameter buf address to bounce buf. */
		bb_args->args[1] = svm_rtas_bbuf_alloc(&svm->mm, &svm->rtas);
		if (!bb_args->args[1])
			return RTAS_HDLR_ERR;

		if (svm_rtas_bbuf_memcpy(&svm->mm,
				         bb_args->args[1],
				         guest_args->args[1],
					 length) != length) {

			svm_rtas_bbuf_free(&svm->rtas, bb_args->args[1]);
			bb_args->args[1] = 0;
			return RTAS_HDLR_ERR;
		}
	} else {
		svm_rtas_dprintf("[POST] ibm_set_sys_param token 0x%x"
				 " status [%d]\n",
				 guest_args->token, guest_args->args[2]);

		svm_rtas_bbuf_free(&svm->rtas, bb_args->args[1]);
	}

	return RTAS_HDLR_OK;
}

/*
 *   - Token for ibm,slot-error-detail
 *   - nargs 8
 *   - nret 1
 *   - args[0] = Config_addr
 *   - args[1] = PHB_Unit_ID_Hi
 *   - args[2] = PHB_Unit_ID_Low
 *   - args[3] = Device_Driver_Error_Buffer
 *   - args[4] = Device_Driver_Error_Buffer_Length
 *   - args[5] = Returned_Error_Buffer
 *   - args[6] = Returned_Error_Buffer_Length
 *   - args[7] = Function
 *   - ret = args[8] = Status
 *
 */
static enum rtas_hdlr_ret
svm_rtas_ibm_slot_err_det_hdlr(enum rtas_hdlr_type type,
			       struct svm *svm __unused,
			       struct rtas_args *guest_args __unused,
			       struct rtas_args *bb_args __unused)
{
	if (type == RTAS_HDLR_PRE) {
		svm_rtas_dprintf("[PRE] ibm_slot_err_det token 0x%x\n",
				 bb_args->token);
	} else {
		svm_rtas_dprintf("[POST] ibm_slot_err_det token 0x%x"
				 " status [%d]\n",
				 guest_args->token, guest_args->args[8]);
	}

	return RTAS_HDLR_OK;
}

/*
 *   - Token for nvram-fetch
 *   - nargs 3
 *   - nret 2
 *   - args[0] = Index  - Byte offset in NVRAM
 *   - args[1] = Buffer - Real address of data buffer
 *   - args[2] = Length - Size of data buffer (in bytes)
 *   - ret = args[3] = Status
 *   - ret = args[4] = Num - Number of bytes successfully copied
 *
 */
static enum rtas_hdlr_ret
svm_rtas_nvram_fetch_hdlr(enum rtas_hdlr_type type,
			  struct svm *svm,
			  struct rtas_args *guest_args,
			  struct rtas_args *bb_args)
{
	enum rtas_hdlr_ret ret = RTAS_HDLR_OK;

	if (type == RTAS_HDLR_PRE) {
		svm_rtas_dprintf("[PRE] nvram_fetch token 0x%x\n",
				 bb_args->token);

		/* Verfiy nvram_fetch length */
		if (bb_args->args[2] > RTAS_BUF_BBUF_SZ)
			return RTAS_HDLR_ERR;

		/* Set nvram_fetch buf address to address of bounce buf. */
		bb_args->args[1] = svm_rtas_bbuf_alloc(&svm->mm, &svm->rtas);
		if (!bb_args->args[1])
			return RTAS_HDLR_ERR;
	} else {
		/* nvram-fetch Status in args[3] */
		int status = guest_args->args[3];

		svm_rtas_dprintf("[POST] nvram_fetch token 0x%x"
				 " status [%d]\n",
				 guest_args->token, status);

		if (status == 0 &&
		    svm_rtas_bbuf_memcpy(&svm->mm,
				guest_args->args[1],
				bb_args->args[1],
				guest_args->args[4]) != guest_args->args[4])
			ret = RTAS_HDLR_ERR;

		svm_rtas_bbuf_free(&svm->rtas, bb_args->args[1]);
	}

	return ret;
}

/*
 *   - Token for nvram-store
 *   - nargs 3
 *   - nret 2
 *   - args[0] = Index  - Byte offset in NVRAM
 *   - args[1] = Buffer - Real address of data buffer
 *   - args[2] = Length - Size of data buffer (in bytes)
 *   - ret = args[3] = Status
 *   - ret = args[4] = Num - Number of bytes successfully copied
 *
 */
static enum rtas_hdlr_ret
svm_rtas_nvram_store_hdlr(enum rtas_hdlr_type type,
			  struct svm *svm,
			  struct rtas_args *guest_args,
			  struct rtas_args *bb_args)
{
	if (type == RTAS_HDLR_PRE) {
		svm_rtas_dprintf("[PRE] nvram_store token 0x%x\n",
				 bb_args->token);

		/* Verfiy nvram_store length */
		if (bb_args->args[2] > RTAS_BUF_BBUF_SZ)
			return RTAS_HDLR_ERR;

		/* Set nvram_store buf address to address of bounce buf. */
		bb_args->args[1] = svm_rtas_bbuf_alloc(&svm->mm, &svm->rtas);
		if (!bb_args->args[1])
			return RTAS_HDLR_ERR;

		if (svm_rtas_bbuf_memcpy(&svm->mm,
				bb_args->args[1],
				guest_args->args[1],
				bb_args->args[2]) != bb_args->args[2]) {
			svm_rtas_bbuf_free(&svm->rtas, bb_args->args[1]);
			bb_args->args[1] = 0;
		}
	} else {
		svm_rtas_dprintf("[POST] nvram_store token 0x%x"
				 " status [%d]\n",
				 guest_args->token, guest_args->args[3]);

		svm_rtas_bbuf_free(&svm->rtas, bb_args->args[1]);
	}

	return RTAS_HDLR_OK;
}

/*
 *   - Token for power-off
 *   - nargs 2
 *   - nret 1
 *   - args[0] = Mask of events that can cause a power on event
 *   - args[1] = Mask of events that can cause a power on event
 *   - ret = args[2] = Status
 *
 */
static enum rtas_hdlr_ret
svm_rtas_pwr_off_hdlr(enum rtas_hdlr_type type,
		      struct svm *svm __unused,
		      struct rtas_args *guest_args __unused,
		      struct rtas_args *bb_args __unused)
{
	if (type == RTAS_HDLR_PRE) {
		svm_rtas_dprintf("pwr_off token 0x%x\n", bb_args->token);
	} else {
		svm_rtas_dprintf("[POST] pwr_off token 0x%x"
				 " status [%d]\n",
				 guest_args->token, guest_args->args[2]);
	}

	return RTAS_HDLR_OK;
}

/*
 * Begin the process of starting up a new CPU (in response to an RTAS
 * 'start-cpu' call). Save the state from the RTAS call here.
 *
 * Our caller will reflect this call to HV and when the HV starts up
 * the new CPU (and issues uv_return()), rtas_start_cpu_end() will
 * finish setting up the new CPU.
 *
 * When reflecting an hcall to HV, we normally store a cookie in R31.
 * But for 'start-cpu', we cannot use R31 since HV clears all registers
 * in the new CPU except R3:R5. So we save the 'r3_contents' field from
 * the rtas_args buffer and replace this field with a "start-cpu cookie".
 *
 * When HV starts up the new CPU, it will copy this cookie to R3 of the
 * new CPU and rtas_start_cpu_end() will get the cookie from R3.
 */
static void rtas_start_cpu_begin(struct svm *svm,
				 struct rtas_args *rtas_args)
{
	struct start_cpu_state *start_cpu;

	start_cpu = zalloc(sizeof(*start_cpu));
	assert(start_cpu);

	/*
	 * @todo ref count svm?
	 */
	start_cpu->svm = svm;
	start_cpu->cpu_id = rtas_args->args[0];
	start_cpu->start_here = rtas_args->args[1];
	start_cpu->r3_contents = rtas_args->args[2];

	rtas_args->args[2] = (uint32_t)svm_generate_cookie(svm,
							   start_cpu,
							   HSRR0_MASK,
							   MAX_EXCEPTION);
}

static enum rtas_hdlr_ret
svm_rtas_start_cpu_hdlr(enum rtas_hdlr_type type,
			struct svm *svm,
			struct rtas_args *guest_args __unused,
			struct rtas_args *bb_args)
{
	if (type == RTAS_HDLR_PRE) {
		svm_rtas_dprintf("start-cpu token 0x%x\n", bb_args->token);
		rtas_start_cpu_begin(svm, bb_args);
	}

	return RTAS_HDLR_OK;
}

/*
 *   - Token for ibm,nmi-register
 *   - nargs 2
 *   - nret 1
 *   - args[0] = Real address of fwnmi reset interrupt handler
 *   - args[1] = Real address of fwmni machine check interrupt handler
 *   - ret = args[2] = Status
 *
 */
static enum rtas_hdlr_ret svm_rtas_ibm_nmi_register(enum rtas_hdlr_type type,
					  struct svm *svm,
					  struct rtas_args *guest_args,
					  struct rtas_args *bb_args)
{
	if (type == RTAS_HDLR_PRE) {
		svm_rtas_dprintf("[PRE] ibm,nmi-register token 0x%x\n",
				 bb_args->token);
	} else {
		int status = guest_args->args[2];

		svm_rtas_dprintf("[POST] ibm,nmi-register token 0x%x"
				 " status [%d]\n",
				 guest_args->token, status);
		if (status)
			pr_error("%s: status [%d]\n", __func__, status);
		else
			svm->fwnmi_machine_check_addr = bb_args->args[1];
	}

	return RTAS_HDLR_OK;
}

/*
 * @todo: Move this information to a per-SVM data structure.
 *
 * The problem is that the token value is a property of the QEMU instance, and
 * thus can vary from SVM to SVM (though in a well-behaved environment that
 * should be rare). Therefore, the Ultravisor needs to keep these tokens in a
 * per-SVM structure, so that each QEMU instance is allowed to have its own
 * different values for these tokens.
 *
 * As the code currently stands, a malicious QEMU can cause confusion in the
 * Ultravisor by changing the value of the RTAS tokens it uses, which will
 * affect all other SVMs.
 *
 * Since in almost all cases the RTAS tokens will be the same, there should be a
 * scheme where the definitions are shared when it is confirmed that the tokens
 * are indeed the same. This would avoid wasting scarce Ultravisor memory to
 * store redundant information.
 */
struct svm_rtas_hdlr svm_rtas_hdlrs[] = {
	/* Token set during FDT processing */
	{
		.service = "check-exception",
		.handler = svm_rtas_chk_excp_hdlr,
	},

	{
		.service = "event-scan",
		.handler = svm_rtas_event_scan_hdlr,
	},

	{
		.service = "ibm,configure-connector",
		.handler = svm_rtas_ibm_cfg_conn_hdlr,
	},

	{
		.service = "ibm,get-system-parameter",
		.handler = svm_rtas_ibm_get_sys_param_hdlr,
	},

	{
		.service = "ibm,set-system-parameter",
		.handler = svm_rtas_ibm_set_sys_param_hdlr,
	},

	{
		.service = "ibm,slot-error-detail",
		.handler = svm_rtas_ibm_slot_err_det_hdlr,
	},

	{
		.service = "ibm,os-term",
		.handler = svm_rtas_ibm_os_term_hdlr,
	},

	{
		.service = "nvram-fetch",
		.handler = svm_rtas_nvram_fetch_hdlr,
	},

	{
		.service = "nvram-store",
		.handler = svm_rtas_nvram_store_hdlr,
	},

	{
		.service = "power-off",
		.handler = svm_rtas_pwr_off_hdlr,
	},

	{
		.service = "start-cpu",
		.handler = svm_rtas_start_cpu_hdlr,
	},

	{
		.service = "ibm,nmi-register",
		.handler = svm_rtas_ibm_nmi_register,
		.optional = true,
	},

	{ 0, NULL, NULL, 0 },
};
