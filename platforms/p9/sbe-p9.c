// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * P9 OPAL - SBE communication driver
 *
 * Copyright 2019 IBM Corp.
 */

#define pr_fmt(fmt) "SBE-P9: " fmt

#include <chip.h>
#include <lock.h>
#include <xscom.h>
#include <logging.h>
#include <mem_region-malloc.h>
#include <sbe-chipops.h>
#include <uvcall.h>
#include "sbe-p9.h"

enum sbe_chipop_ops {
	SBE_CHIPOP_TIMER,
	SBE_CHIPOP_HANDLE_INTERRUPT,
	SBE_CHIPOP_START_MPIPL,
	SBE_CHIPOP_MAX
};

enum p9_sbe_mbox_state {
	sbe_mbox_idle = 0,	/* Ready to send message */
	sbe_mbox_send,		/* Message sent, waiting for ack/response */
	sbe_mbox_rr,		/* SBE in R/R */
};

struct p9_sbe {
	/* Chip ID to send message */
	u32			chip_id;

	struct lock		lock;

	enum p9_sbe_mbox_state	state;

	/* SBE MBOX message sequence number */
	u16			cur_seq;
};

/* Timer control message */
static struct p9_sbe_msg *timer_ctrl_msg;

static u64 p9_sbe_rreg(u32 chip_id, u64 reg)
{
	u64 data = 0;
	int rc;

	rc = xscom_read(chip_id, reg, &data);
	if (rc) {
		pr_debug("XSCOM error %d reading reg 0x%llx\n", rc, reg);
		return 0xffffffff;
	}

	return be64_to_cpu(data);
}

static void p9_sbe_reg_dump(u32 chip_id)
{
#define SBE_DUMP_REG_ONE(chip_id, x)					\
	pr_debug("  %20s: %016llx\n", #x, p9_sbe_rreg(chip_id, x))

	pr_debug("MBOX register dump for chip : %x\n", chip_id);
	SBE_DUMP_REG_ONE(chip_id, PSU_SBE_DOORBELL_REG_RW);
	SBE_DUMP_REG_ONE(chip_id, PSU_HOST_SBE_MBOX_REG0);
	SBE_DUMP_REG_ONE(chip_id, PSU_HOST_SBE_MBOX_REG1);
	SBE_DUMP_REG_ONE(chip_id, PSU_HOST_SBE_MBOX_REG2);
	SBE_DUMP_REG_ONE(chip_id, PSU_HOST_SBE_MBOX_REG3);
	SBE_DUMP_REG_ONE(chip_id, PSU_HOST_DOORBELL_REG_RW);
	SBE_DUMP_REG_ONE(chip_id, PSU_HOST_SBE_MBOX_REG4);
	SBE_DUMP_REG_ONE(chip_id, PSU_HOST_SBE_MBOX_REG5);
	SBE_DUMP_REG_ONE(chip_id, PSU_HOST_SBE_MBOX_REG6);
	SBE_DUMP_REG_ONE(chip_id, PSU_HOST_SBE_MBOX_REG7);
}

static void p9_sbe_fillmsg(struct p9_sbe_msg *msg, u16 cmd,
			   u16 ctrl_flag, u64 reg1, u64 reg2, u64 reg3)
{
	bool response = !!(ctrl_flag & SBE_CMD_CTRL_RESP_REQ);
	u16 flag;

	/*
	 * Always set ack required flag. SBE will interrupt OPAL once it read
	 * message from mailbox register. If OPAL is expecting response, then
	 * it will update message timeout, otherwise it will send next message.
	 */
	flag = ctrl_flag | SBE_CMD_CTRL_ACK_REQ;

	/* Seqence ID is filled by p9_sbe_queue_msg() */
	msg->reg[0] = ((u64)flag << 32) | cmd;
	msg->reg[1] = reg1;
	msg->reg[2] = reg2;
	msg->reg[3] = reg3;
	msg->response = response;
}

static struct p9_sbe_msg *p9_sbe_allocmsg(bool alloc_resp)
{
	struct p9_sbe_msg *msg;

	msg = zalloc(sizeof(struct p9_sbe_msg));
	if (!msg) {
		pr_error("Failed to allocate SBE message\n");
		return NULL;
	}
	if (alloc_resp) {
		msg->resp = zalloc(sizeof(struct p9_sbe_msg));
		if (!msg->resp) {
			pr_error("Failed to allocate SBE resp message\n");
			free(msg);
			return NULL;
		}
	}

	return msg;
}

/*
 * Allocate and populate p9_sbe_msg structure
 * Handles "command with direct data" format only.
 *
 * Note: All mbox messages of our interest uses direct data format. If we need
 *       indirect data format then we may have to enhance this function.
 */
static struct p9_sbe_msg *p9_sbe_mkmsg(u16 cmd, u16 ctrl_flag,
				       u64 reg1, u64 reg2, u64 reg3)
{
	struct p9_sbe_msg *msg;

	msg = p9_sbe_allocmsg(!!(ctrl_flag & SBE_CMD_CTRL_RESP_REQ));
	if (!msg)
		return NULL;

	p9_sbe_fillmsg(msg, cmd, ctrl_flag, reg1, reg2, reg3);
	return msg;
}

static bool p9_sbe_mbox_busy(struct p9_sbe *sbe)
{
	return (sbe->state != sbe_mbox_idle);
}

static struct p9_sbe *p9_sbe_get_sbe(u32 chip_id)
{
	struct proc_chip *chip;

	chip = get_chip(chip_id);
	if (chip == NULL)
		return NULL;

	return chip->sbe;
}

static int p9_sbe_msg_send(struct p9_sbe *sbe, struct p9_sbe_msg *msg)
{
	int rc, i;
	u64 addr, *data;

	if (p9_sbe_mbox_busy(sbe))
		return U_BUSY;

	msg->reg[0] = msg->reg[0] | ((u64)sbe->cur_seq << 16);
	sbe->cur_seq++;

	/* Reset sequence number */
	if (sbe->cur_seq == 0xffff)
		sbe->cur_seq = 1;

	addr = PSU_HOST_SBE_MBOX_REG0;
	data = &msg->reg[0];

	for (i = 0; i < NR_HOST_SBE_MBOX_REG; i++) {
		rc = xscom_write(sbe->chip_id, addr, *data);
		if (rc)
			return rc;

		addr++;
		data++;
	}

	rc = xscom_write(sbe->chip_id, PSU_SBE_DOORBELL_REG_OR,
			 HOST_SBE_MSG_WAITING);
	if (rc != U_SUCCESS)
		return rc;

	prlog(PR_TRACE, "Message queued [chip id = 0x%x]:\n", sbe->chip_id);
	for (i = 0; i < 4; i++)
		prlog(PR_TRACE, "    Reg%d : %016llx\n", i, msg->reg[i]);

	sbe->state = sbe_mbox_send;

	return rc;
}

static int p9_sbe_clear_interrupt(struct p9_sbe *sbe, u64 bits)
{
	int rc;
	u64 val;

	/* Clear doorbell register */
	val = SBE_HOST_RESPONSE_MASK & ~bits;
	rc = xscom_write(sbe->chip_id, PSU_HOST_DOORBELL_REG_AND, val);
	if (rc) {
		pr_error("Failed to clear SBE to Host doorbell "
			 "interrupt [chip id = %x]\n", sbe->chip_id);
	}
	return rc;
}

static int p9_sbe_interrupt(struct p9_sbe *sbe, uint64_t *doorbell)
{
	int rc;
	uint64_t data, val;

	*doorbell = 0;

 again:
	/* Read doorbell register */
	rc = xscom_read(sbe->chip_id, PSU_HOST_DOORBELL_REG_RW, &data);
	if (rc) {
		pr_error("Failed to read SBE to Host doorbell register "
			 "[chip id = %x]\n", sbe->chip_id);
		p9_sbe_reg_dump(sbe->chip_id);
		return rc;
	}

	/* Completed processing all the bits */
	if (!data)
		return U_SUCCESS;

	/* SBE came back from reset */
	if (data & SBE_HOST_RESET) {
		/* Clear all bits and restart sending message */
		rc = p9_sbe_clear_interrupt(sbe, data);
		if (rc)
			return rc;

		pr_notice("Back from reset [chip id = %x]\n", sbe->chip_id);
		/* Reset SBE MBOX state */
		sbe->state = sbe_mbox_idle;
		*doorbell |= SBE_HOST_RESET;

		return U_SUCCESS;
	}

	/* Process ACK message before response */
	if (data & SBE_HOST_MSG_READ) {
		rc = p9_sbe_clear_interrupt(sbe, SBE_HOST_MSG_READ);
		if (rc)
			return rc;

		sbe->state = sbe_mbox_idle;
		*doorbell |= SBE_HOST_MSG_READ;

		goto again;
	}

	/* SBE passthrough command, call prd handler */
	if (data & SBE_HOST_PASSTHROUGH) {
		rc = p9_sbe_clear_interrupt(sbe, SBE_HOST_PASSTHROUGH);
		if (rc)
			return rc;

		*doorbell |= SBE_HOST_PASSTHROUGH;

		goto again;
	}

	/* Timer expired */
	if (data & SBE_HOST_TIMER_EXPIRY) {
		rc = p9_sbe_clear_interrupt(sbe, SBE_HOST_TIMER_EXPIRY);
		if (rc)
			return rc;

		*doorbell |= SBE_HOST_TIMER_EXPIRY;

		goto again;
	}

	/* Unhandled bits */
	val = data & ~(SBE_HOST_RESPONSE_MASK);
	if (val) {
		pr_error("Unhandled interrupt bit [chip id = %x] : "
			 " %016llx\n", sbe->chip_id, val);
		rc = p9_sbe_clear_interrupt(sbe, data);
		if (rc)
			return rc;
		goto again;
	}

	return U_SUCCESS;
}

static int sbe_update_timer(struct p9_sbe *sbe, uint64_t new_target)
{
	int rc;

	/* Clear sequence number. p9_sbe_queue_msg will add new sequene ID */
	timer_ctrl_msg->reg[0] &= ~(PPC_BITMASK(32, 47));
	/* Update timeout value */
	timer_ctrl_msg->reg[1] = new_target;

	rc = p9_sbe_msg_send(sbe, timer_ctrl_msg);

	return rc;
}

int send_sbe_command(uint64_t chip_id, uint64_t opcode, uint64_t input,
		     uint64_t *output)
{
	int rc;
	struct p9_sbe *sbe;

	if (opcode >= SBE_CHIPOP_MAX)
		return U_PARAMETER;

	/* 
	 * @todo : ensure that input and output is a valid address.
	 * It should not be pointing to secure memory
	 */

	sbe = p9_sbe_get_sbe(chip_id);
	if (sbe == NULL)
		return U_PARAMETER;

	lock(&sbe->lock);

	switch(opcode) {
	case SBE_CHIPOP_TIMER:
		rc = sbe_update_timer(sbe, input);
		break;
	case SBE_CHIPOP_HANDLE_INTERRUPT:
		/*
		 * Ensure input is zero so that it can be used in the future
		 * (for example, to pass option flags) if necessary.
		*/
		if (input) {
			rc = U_PARAMETER;
			break;
		}
		rc = p9_sbe_interrupt(sbe, output);
		break;
	case SBE_CHIPOP_START_MPIPL:
		/*
		 * Ensure input is zero so that it can be used in the future
		 * (for example, to pass option flags) if necessary.
		 */
		if (input) {
			rc = U_PARAMETER;
			break;
		}
		rc = xscom_write(chip_id, SBE_CONTROL_REG_RW,
				 SBE_CONTROL_REG_S0);
		break;
	default:
		rc = U_PARAMETER;
	}

	unlock(&sbe->lock);
	return rc;
}

void sbe_init(void)
{
	struct dt_node *xn;
	struct proc_chip *chip;
	struct p9_sbe *sbe;

	dt_for_each_compatible(dt_root, xn, "ibm,xscom") {
		sbe = zalloc(sizeof(struct p9_sbe));
		assert(sbe);
		sbe->chip_id = dt_get_chip_id(xn);
		sbe->cur_seq = 1;
		sbe->state = sbe_mbox_idle;
		init_lock(&sbe->lock);

		chip = get_chip(sbe->chip_id);
		assert(chip);
		chip->sbe = sbe;
	}

	/* Prepare SBE timer message. */
	timer_ctrl_msg = p9_sbe_mkmsg(SBE_CMD_CONTROL_TIMER,
				      CONTROL_TIMER_START, 0, 0, 0);
	assert(timer_ctrl_msg);
}
