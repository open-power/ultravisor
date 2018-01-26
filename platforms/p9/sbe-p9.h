// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2017-2019 IBM Corp.
 */

#ifndef __SBE_P9_H
#define __SBE_P9_H

/* Number of MBOX register on each side */
#define NR_HOST_SBE_MBOX_REG		0x04

/*
 * SBE MBOX register address
 *   Reg 0 - 3 : Host to send command packets to SBE
 *   Reg 4 - 7 : SBE to send response packets to Host
 */
#define PSU_HOST_SBE_MBOX_REG0		0x000D0050
#define PSU_HOST_SBE_MBOX_REG1		0x000D0051
#define PSU_HOST_SBE_MBOX_REG2		0x000D0052
#define PSU_HOST_SBE_MBOX_REG3		0x000D0053
#define PSU_HOST_SBE_MBOX_REG4		0x000D0054
#define PSU_HOST_SBE_MBOX_REG5		0x000D0055
#define PSU_HOST_SBE_MBOX_REG6		0x000D0056
#define PSU_HOST_SBE_MBOX_REG7		0x000D0057
#define PSU_SBE_DOORBELL_REG_RW		0x000D0060
#define PSU_SBE_DOORBELL_REG_AND	0x000D0061
#define PSU_SBE_DOORBELL_REG_OR		0x000D0062
#define PSU_HOST_DOORBELL_REG_RW	0x000D0063
#define PSU_HOST_DOORBELL_REG_AND	0x000D0064
#define PSU_HOST_DOORBELL_REG_OR	0x000D0065

/*
 * Doorbell register to trigger SBE interrupt. Set by OPAL to inform
 * the SBE about a waiting message in the Host/SBE mailbox registers
 */
#define HOST_SBE_MSG_WAITING		PPC_BIT(0)

/*
 * Doorbell register for host bridge interrupt. Set by the SBE to inform
 * host about a response message in the Host/SBE mailbox registers
 */
#define SBE_HOST_RESPONSE_WAITING	PPC_BIT(0)
#define SBE_HOST_MSG_READ		PPC_BIT(1)
#define SBE_HOST_STOP15_EXIT		PPC_BIT(2)
#define SBE_HOST_RESET			PPC_BIT(3)
#define SBE_HOST_PASSTHROUGH		PPC_BIT(4)
#define SBE_HOST_TIMER_EXPIRY		PPC_BIT(14)
#define SBE_HOST_RESPONSE_MASK		(PPC_BITMASK(0, 4) | SBE_HOST_TIMER_EXPIRY)

/* SBE Control Register */
#define SBE_CONTROL_REG_RW		0x00050008

/* SBE interrupt s0/s1 bits */
#define SBE_CONTROL_REG_S0		PPC_BIT(14)
#define SBE_CONTROL_REG_S1		PPC_BIT(15)

/*
 * Commands are provided in xxyy form where:
 *   - xx : command class
 *   - yy : command
 *
 * Both request and response message uses same seq ID,
 * command class and command.
 */
#define SBE_CMD_CTRL_DEADMAN_LOOP	0xD101
#define SBE_CMD_MULTI_SCOM		0xD201
#define SBE_CMD_PUT_RING_FORM_IMAGE	0xD301
#define SBE_CMD_CONTROL_TIMER		0xD401
#define SBE_CMD_GET_ARCHITECTED_REG	0xD501
#define SBE_CMD_CLR_ARCHITECTED_REG	0xD502
#define SBE_CMD_SET_UNSEC_MEM_WINDOW	0xD601
#define SBE_CMD_GET_SBE_FFDC		0xD701
#define SBE_CMD_GET_CAPABILITY		0xD702
#define SBE_CMD_READ_SBE_SEEPROM	0xD703
#define SBE_CMD_SET_FFDC_ADDR		0xD704
#define SBE_CMD_QUIESCE_SBE		0xD705
#define SBE_CMD_SET_FABRIC_ID_MAP	0xD706
#define SBE_CMD_STASH_MPIPL_CONFIG	0xD707

/* SBE MBOX control flags */

/* Generic flags */
#define SBE_CMD_CTRL_RESP_REQ		0x0100
#define SBE_CMD_CTRL_ACK_REQ		0x0200

/* Control timer */
#define CONTROL_TIMER_START		0x0001
#define CONTROL_TIMER_STOP		0x0002

/* SBE message */
struct p9_sbe_msg {
	/*
	 * Reg[0] :
	 *   word0 :
	 *     direct cmd  : reserved << 16 | ctrl flag
	 *     indirect cmd: mem_addr_size_dword
	 *     response    : primary status << 16 | secondary status
	 *
	 *   word1 : seq id << 16 | cmd class << 8 | cmd
	 *
	 * WARNING:
	 *   - Don't populate reg[0].seq (byte 4,5). This will be populated by
	 *     p9_sbe_queue_msg().
	 */
	u64	reg[4];

	/* Set if the message expects a response */
	bool			response;

	/* Response will be filled by driver when response received */
	struct p9_sbe_msg	*resp;
};

#endif	/* __SBE_P9_H */
