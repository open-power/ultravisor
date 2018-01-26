/* Copyright 2013-2014 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *
 * SPDX-License-Identifier: GPL-2.0
 * Copyright 2020 IBM Corp.
 *
 */

#ifndef __PROCESSOR_H
#define __PROCESSOR_H

#include <bitutils.h>

/* P7 MSR bits */
#define MSR_SF		PPC_BIT(0)	/* 64-bit mode */
#define MSR_HV		PPC_BIT(3)	/* Hypervisor mode */
#define MSR_TS_T	PPC_BIT(29)	/* TM: Transactional state */
#define MSR_TS_S	PPC_BIT(30)	/* TM: Suspended state */
#define MSR_TM		PPC_BIT(31)	/* Transactional Memory */
#define MSR_VEC		PPC_BIT(38)	/* VMX enable */
#define MSR_VSX		PPC_BIT(40)	/* VSX enable */
#define MSR_S		PPC_BIT(41)	/* Secure (S-bit) */
#define MSR_EE		PPC_BIT(48)	/* External Int. Enable */
#define MSR_PR		PPC_BIT(49)       	/* Problem state */
#define MSR_FP		PPC_BIT(50)	/* Floating Point Enable */
#define MSR_ME		PPC_BIT(51)	/* Machine Check Enable */
#define MSR_FE0		PPC_BIT(52)	/* FP Exception 0 */
#define MSR_SE		PPC_BIT(53)	/* Step enable */
#define MSR_BE		PPC_BIT(54)	/* Branch trace enable */
#define MSR_FE1		PPC_BIT(55)	/* FP Exception 1 */
#define MSR_IR		PPC_BIT(58)	/* Instructions reloc */
#define MSR_DR		PPC_BIT(59)	/* Data reloc */
#define MSR_PMM		PPC_BIT(61)	/* Perf Monitor */
#define MSR_RI		PPC_BIT(62)	/* Recoverable Interrupt */
#define MSR_LE		PPC_BIT(63)	/* Little Endian */

#define MSR_TS_MASK		(MSR_TS_T | MSR_TS_S)
#define MSR_TM_RESV(x)		(((x) & MSR_TS_MASK) == MSR_TS_MASK)
#define MSR_TM_TRANSACTIONAL(x)	(((x) & MSR_TS_MASK) == MSR_TS_T)
#define MSR_TM_SUSPENDED(x)	(((x) & MSR_TS_MASK) == MSR_TS_S)

#define SRR1_SC_MASK	PPC_BITMASK(42, 43)
#define SSR1_SC_LEV0	0	/* Normal System Call */
#define SSR1_SC_LEV1	1	/* Hypercall */
#define SSR1_SC_LEV2	2	/* Ultracall */

/* PIR */
#define SPR_PIR_P9_MASK		0x7fff	/* Mask of implemented bits */
#define SPR_PIR_P8_MASK		0x1fff	/* Mask of implemented bits */
#define SPR_PIR_P7_MASK		0x03ff	/* Mask of implemented bits */

/* SPR register definitions */
#define SPR_DSCR	0x011	/* RW: Data stream control reg */
#define SPR_DSISR	0x012	/* RW: Data storage interrupt status reg */
#define SPR_DAR		0x013	/* RW: Data address reg */
#define SPR_DEC		0x016	/* RW: Decrement Register */
#define SPR_SDR1	0x019
#define SPR_SRR0	0x01a	/* RW: Exception save/restore reg 0 */
#define SPR_SRR1	0x01b	/* RW: Exception save/restore reg 1 */
#define SPR_CFAR	0x01c	/* RW: Come From Address Register */
#define SPR_AMR		0x01d	/* RW: Authority Mask Register */
#define SPR_IAMR	0x03d	/* RW: Instruction Authority Mask Register */
#define SPR_TIDR	0x090	/* Thread ID register */
#define SPR_UAMOR	0x09d	/* RW: User Authority Mask Override Register */
#define SPR_PSPB	0x09f	/* Problem State Priority Boost Register */
#define SPR_DAWR	0x0b4	/* Data Address Watch Point Register */
#define SPR_DPDES	0x0b0	/* Directed Priv. Doorbell Exc. State */
#define SPR_RPR		0x0ba   /* RW: Relative Priority Register */
#define SPR_CIABR	0x0bb   /* Completed Instruction Address Breakpoint */
#define SPR_DAWRX	0x0bc   /* Data Address Watch Point Register */
#define SPR_HFSCR	0x0be   /* HV=1 Facility Statys and Control Register */
#define SPR_FSCR	0x099   /* Facility Status & Control Register */
#define SPR_VRSAVE	0x100   /* Vector Register Save Register */
#define SPR_TBRL	0x10c	/* RO: Timebase low */
#define SPR_TBRU	0x10d	/* RO: Timebase high */
#define SPR_SPRC	0x114	/* RW: Access to uArch SPRs (ex SCOMC) */
#define SPR_SPRD	0x115	/* RW: Access to uArch SPRs (ex SCOMD) */
#define	SPR_SCOMC	0x114	/* RW: SCOM Control - old name of SPRC */
#define	SPR_SCOMD	0x115	/* RW: SCOM Data    - old name of SPRD */
#define SPR_TBWL	0x11c	/* RW: Timebase low */
#define SPR_TBWU	0x11d	/* RW: Timebase high */
#define SPR_TBU40	0x11e	/* RW: Timebase Upper 40 bit */
#define SPR_PVR		0x11f	/* RO: Processor version register */
#define SPR_HSPRG0	0x130	/* RW: Hypervisor scratch 0 */
#define SPR_HSPRG1	0x131	/* RW: Hypervisor scratch 1 */
#define SPR_HDSISR	0x132	/* RW: HV Data Storage Interrupt Status Reg */
#define SPR_HDAR	0x133	/* RW: Hypervisor Data Access Register */
#define SPR_SPURR	0x134	/* RW: Scaled Processor Utilization Resource */
#define SPR_PURR	0x135	/* RW: Processor Utilization Resource reg */
#define SPR_HDEC	0x136	/* RW: Hypervisor Decrementer */
#define SPR_HRMOR	0x139	/* RW: Hypervisor Real Mode Offset reg */
#define SPR_HSRR0	0x13a	/* RW: HV Exception save/restore reg 0 */
#define SPR_HSRR1	0x13b	/* RW: HV Exception save/restore reg 1 */
#define SPR_TFMR	0x13d
#define SPR_LPCR	0x13e
#define SPR_HMER	0x150	/* Hypervisor Maintenance Exception */
#define SPR_HMEER	0x151	/* HMER interrupt enable mask */
#define SPR_HEIR	0x153	/* Hypervisor Emulated Instruction Register */
#define SPR_AMOR	0x15d
#define SPR_SPRG0	0x110	/* SPGs */
#define SPR_SPRG1	0x111	/* SPGs */
#define SPR_SPRG2	0x112	/* SPGs */
#define SPR_SPRG3	0x113	/* SPGs */
#define SPR_PIDR	0x030	/* RW: Process ID */
#define SPR_LPIDR	0x13f
#define SPR_PTCR	0x1d0	/* Partition table control Register */
#define SPR_USPRG0	0x1f0	/* RW: Ultravisor scratch 0 */
#define SPRG_UVSTACK        SPR_USPRG0
#define SPR_USPRG1	0x1f1	/* RW: Ultravisor scratch 1 */
#define SPRG_UVSCRATCH0     SPR_USPRG1
#define SPR_URMOR	0x1F9	/* RW: Ultravisor Real Mode Offset reg */
#define SPR_USRR0	0x1FA	/* RW: Ultravisor Save/Restore Register */
#define SPR_USRR1	0x1FB	/* RW: Ultravisor Save/Restore Register */
#define SPR_SIER	0x310
#define SPR_MMCRA	0x312
#define SPR_PMC1	0x313
#define SPR_PMC2	0x314
#define SPR_PMC3	0x315
#define SPR_PMC4	0x316
#define SPR_PMC5	0x317
#define SPR_PMC6	0x318
#define SPR_MMCR0	0x31B
#define SPR_SIAR	0x31C
#define SPR_SDAR	0x31D
#define SPR_MMCR1	0x31E
#define SPR_EBBHR	0x324	/* Event based branch handler register */
#define SPR_EBBRR	0x325	/* Event based branch return register */
#define SPR_BESCR	0x326	/* Branch event status and control register */
#define SPR_TAR		0x32F   /* Target Address Register */
#define SPR_ASDR	0x330   /* Access segment descriptor register */
#define SPR_IC		0x350   /* Virtual Instruction Counter */
#define SPR_VTB		0x351   /* Virtual Time Base */
#define SPR_MMCRC	0x353	/* Monitor Mode Control Register C */
#define SPR_PSSCR	0x357   /* RW: Stop status and control (ISA 3) */
#define SPR_PPR		0x380   /* SMT Thread Status Register */
#define SPR_TSCR	0x399
#define SPR_TRACE	0x3ee	/* Trace register */
#define SPR_HID0	0x3f0
#define SPR_HID1	0x3f1
#define SPR_HID2	0x3f8
#define SPR_HID4	0x3f4
#define SPR_HID5	0x3f6
#define SPR_PIR		0x3ff	/* RO: Processor Identification */

/* Bit fields of MMCRA */
#define MMCRA_SAMPLE_ENABLE	PPC_BIT(63)

/* Bit fields of MMCR0 */
#define MMCR0_FC	PPC_BIT(32)
#define MMCR0_PMAE	PPC_BIT(37)
#define MMCR0_BHRBA	PPC_BIT(42)
#define MMCR0_EBE	PPC_BIT(43)
#define MMCR0_PMCC	PPC_BITMASK(44,45)
#define MMCR0_PMAO	PPC_BIT(56)
#define MMCR0_FC56	PPC_BIT(59)
#define MMCR0_FCH	PPC_BIT(63)

/* Bits and fields in HFSCR */
#define HFSCR_MSGP	PPC_BIT(53)
#define HFSCR_EBB	PPC_BIT(56)
#define HFSCR_TM	PPC_BIT(58)
#define HFSCR_BHRB	PPC_BIT(59)
#define HFSCR_PM	PPC_BIT(60)

#define HFSCR_IC_MASK	0xFF
#define HFSCR_IC_SHIFT	56
#define HFSCR_IC_PM	3
#define HFSCR_IC_BHRB	4
#define HFSCR_IC_TM	5
#define HFSCR_IC_EBB	7

/* Bit fields in BESCR */
#define BESCR_GE		PPC_BIT(0)
#define BESCR_EE		PPC_BIT(30)
#define BESCR_PME		PPC_BIT(31)
#define BESCR_EEO		PPC_BIT(62)
#define BESCR_PMEO		PPC_BIT(63)

/* Bit fields in FSCR */
#define FSCR_EBB		PPC_BIT(56)


#define SRR1_PROGTM		0x00200000	/* TM Bad Thing */
#define SRR1_PROGILL		0x00080000ULL 	/* Illegal instruction */

/* Bits in LPCR */

#define SPR_LPCR_P9_LPES	PPC_BIT(60)   /* Log. Part. Environment Sel. */
/* Powersave Exit Cause Enable is different for P7 and P8 */
#define SPR_LPCR_P7_PECE	PPC_BITMASK(49,51)
#define SPR_LPCR_P7_PECE0	PPC_BIT(49)   /* Wake on external interrupts */
#define SPR_LPCR_P7_PECE1	PPC_BIT(50)   /* Wake on decrementer */
#define SPR_LPCR_P7_PECE2	PPC_BIT(51)   /* Wake on MCs, HMIs, etc... */

#define SPR_LPCR_P8_PECE	PPC_BITMASK(47,51)
#define SPR_LPCR_P8_PECE0	PPC_BIT(47)   /* Wake on priv doorbell */
#define SPR_LPCR_P8_PECE1	PPC_BIT(48)   /* Wake on hv doorbell */
#define SPR_LPCR_P8_PECE2	PPC_BIT(49)   /* Wake on external interrupts */
#define SPR_LPCR_P8_PECE3	PPC_BIT(50)   /* Wake on decrementer */
#define SPR_LPCR_P8_PECE4	PPC_BIT(51)   /* Wake on MCs, HMIs, etc... */

#define SPR_LPCR_P9_PECE	(PPC_BITMASK(47,51) | PPC_BITMASK(17,17))
#define SPR_LPCR_P9_PECEU0	PPC_BIT(17)   /* Wake on HVI */
#define SPR_LPCR_ONL		PPC_BIT(45)   /* Online - PURR/SPURR count */
#define SPR_LPCR_P9_PECEL0	PPC_BIT(47)   /* Wake on priv doorbell */
#define SPR_LPCR_P9_PECEL1	PPC_BIT(48)   /* Wake on hv doorbell */
#define SPR_LPCR_P9_PECEL2	PPC_BIT(49)   /* Wake on external interrupts */
#define SPR_LPCR_P9_PECEL3	PPC_BIT(50)   /* Wake on decrementer */
#define SPR_LPCR_P9_PECEL4	PPC_BIT(51)   /* Wake on MCs, HMIs, etc... */
#define SPR_LPCR_P9_LD		PPC_BIT(46)   /* Large decrementer mode bit */
#define SPR_LPCR_P9_UPRT	PPC_BIT(41)   /* Use Process Table */
#define SPR_LPCR_P9_HR		PPC_BIT(43)   /* Host Radix */


/* Bits in TFMR - control bits */
#define SPR_TFMR_MAX_CYC_BET_STEPS	PPC_BITMASK(0,7)
#define SPR_TFMR_N_CLKS_PER_STEP	PPC_BITMASK(8,9)
#define SPR_TFMR_MASK_HMI		PPC_BIT(10)
#define SPR_TFMR_SYNC_BIT_SEL		PPC_BITMASK(11,13)
#define SPR_TFMR_TB_ECLIPZ		PPC_BIT(14)
#define SPR_TFMR_LOAD_TOD_MOD		PPC_BIT(16)
#define SPR_TFMR_MOVE_CHIP_TOD_TO_TB	PPC_BIT(18)
#define SPR_TFMR_CLEAR_TB_ERRORS	PPC_BIT(24)
/* Bits in TFMR - thread indep. status bits */
#define SPR_TFMR_HDEC_PARITY_ERROR	PPC_BIT(26)
#define SPR_TFMR_TBST_CORRUPT		PPC_BIT(27)
#define SPR_TFMR_TBST_ENCODED		PPC_BITMASK(28,31)
#define SPR_TFMR_TBST_LAST		PPC_BITMASK(32,35)
#define SPR_TFMR_TB_ENABLED		PPC_BIT(40)
#define SPR_TFMR_TB_VALID		PPC_BIT(41)
#define SPR_TFMR_TB_SYNC_OCCURED	PPC_BIT(42)
#define SPR_TFMR_TB_MISSING_SYNC	PPC_BIT(43)
#define SPR_TFMR_TB_MISSING_STEP	PPC_BIT(44)
#define SPR_TFMR_TB_RESIDUE_ERR		PPC_BIT(45)
#define SPR_TFMR_FW_CONTROL_ERR		PPC_BIT(46)
#define SPR_TFMR_CHIP_TOD_STATUS	PPC_BITMASK(47,50)
#define SPR_TFMR_CHIP_TOD_INTERRUPT	PPC_BIT(51)
#define SPR_TFMR_CHIP_TOD_TIMEOUT	PPC_BIT(54)
#define SPR_TFMR_CHIP_TOD_PARITY_ERR	PPC_BIT(56)
/* Bits in TFMR - thread specific. status bits */
#define SPR_TFMR_PURR_PARITY_ERR	PPC_BIT(57)
#define SPR_TFMR_SPURR_PARITY_ERR	PPC_BIT(58)
#define SPR_TFMR_DEC_PARITY_ERR		PPC_BIT(59)
#define SPR_TFMR_TFMR_CORRUPT		PPC_BIT(60)
#define SPR_TFMR_PURR_OVERFLOW		PPC_BIT(61)
#define SPR_TFMR_SPURR_OVERFLOW		PPC_BIT(62)

/* Bits in HMER/HMEER */
#define SPR_HMER_MALFUNCTION_ALERT	PPC_BIT(0)
#define SPR_HMER_PROC_RECV_DONE		PPC_BIT(2)
#define SPR_HMER_PROC_RECV_ERROR_MASKED	PPC_BIT(3)
#define SPR_HMER_TFAC_ERROR		PPC_BIT(4)
#define SPR_HMER_TFMR_PARITY_ERROR	PPC_BIT(5)
#define SPR_HMER_XSCOM_FAIL		PPC_BIT(8)
#define SPR_HMER_XSCOM_DONE		PPC_BIT(9)
#define SPR_HMER_PROC_RECV_AGAIN	PPC_BIT(11)
#define SPR_HMER_WARN_RISE		PPC_BIT(14)
#define SPR_HMER_WARN_FALL		PPC_BIT(15)
#define SPR_HMER_SCOM_FIR_HMI		PPC_BIT(16)
#define SPR_HMER_TRIG_FIR_HMI		PPC_BIT(17)
#define SPR_HMER_HYP_RESOURCE_ERR	PPC_BIT(20)
#define SPR_HMER_XSCOM_STATUS		PPC_BITMASK(21,23)

/* EA Bits */
#define EA_0	PPC_BIT(0)
#ifndef NO_RMOR
#define NO_RMOR(x)	((u64)((u64)(x) | PPC_BIT(0)))
#endif

/*
 * HMEER: initial bits for HMI interrupt enable mask.
 * Per Dave Larson, never enable 8,9,21-23
 */
#define SPR_HMEER_HMI_ENABLE_MASK	(SPR_HMER_MALFUNCTION_ALERT |\
					 SPR_HMER_HYP_RESOURCE_ERR |\
					 SPR_HMER_PROC_RECV_DONE |\
					 SPR_HMER_PROC_RECV_ERROR_MASKED |\
					 SPR_HMER_TFAC_ERROR |\
					 SPR_HMER_TFMR_PARITY_ERROR |\
					 SPR_HMER_PROC_RECV_AGAIN)

/* Bits in HID0 */
#define SPR_HID0_POWER8_4LPARMODE	PPC_BIT(2)
#define SPR_HID0_POWER8_2LPARMODE	PPC_BIT(6)
#define SPR_HID0_POWER8_DYNLPARDIS	PPC_BIT(15)
#define SPR_HID0_POWER8_HILE		PPC_BIT(19)
#define SPR_HID0_POWER9_HILE		PPC_BIT(4)
#define SPR_HID0_POWER8_ENABLE_ATTN	PPC_BIT(31)
#define SPR_HID0_POWER9_ENABLE_ATTN	(PPC_BIT(2) | PPC_BIT(3))
#define SPR_HID0_POWER9_RADIX		PPC_BIT(8)

/* PVR bits */
#define SPR_PVR_TYPE			0xffff0000
#define SPR_PVR_VERS_MAJ		0x00000f00
#define SPR_PVR_VERS_MIN		0x000000ff

#define PVR_TYPE(_pvr)		GETFIELD(SPR_PVR_TYPE, _pvr)
#define PVR_VERS_MAJ(_pvr)	GETFIELD(SPR_PVR_VERS_MAJ, _pvr)
#define PVR_VERS_MIN(_pvr)	GETFIELD(SPR_PVR_VERS_MIN, _pvr)

/* PVR definitions */
#define PVR_TYPE_P7	0x003f
#define PVR_TYPE_P7P	0x004a
#define PVR_TYPE_P8E	0x004b /* Murano */
#define PVR_TYPE_P8	0x004d /* Venice */
#define PVR_TYPE_P8NVL	0x004c /* Naples */
#define PVR_TYPE_P9	0x004e
#define PVR_TYPE_P9PRI	0x004f

#ifdef __ASSEMBLY__

/* Thread priority control opcodes */
#define smt_low		or 1,1,1
#define smt_medium	or 2,2,2
#define smt_high	or 3,3,3
#define smt_medium_high	or 5,5,5
#define smt_medium_low	or 6,6,6
#define smt_extra_high	or 7,7,7
#define smt_very_low	or 31,31,31
#define smt_lowest	smt_low ; smt_very_low

#else /* __ASSEMBLY__ */

#include <compiler.h>
#include <stdint.h>
#include <stdbool.h>

static inline bool is_power9n(uint32_t version)
{
	if (PVR_TYPE(version) != PVR_TYPE_P9 &&
	    PVR_TYPE(version) != PVR_TYPE_P9PRI)
		return false;
	/*
	 * Bit 13 tells us:
	 *   0 = Scale out (aka Nimbus)
	 *   1 = Scale up  (aka Cumulus)
	 */
	if ((version >> 13) & 1)
		return false;
	return true;
}

/*
 * SMT priority
 */

static inline void smt_low(void)	{ asm volatile("or 1,1,1");	}
static inline void smt_medium(void) 	{ asm volatile("or 2,2,2");	}
static inline void smt_high(void)	{ asm volatile("or 3,3,3");	}
static inline void smt_medium_high(void){ asm volatile("or 5,5,5");	}
static inline void smt_medium_low(void)	{ asm volatile("or 6,6,6");	}
static inline void smt_extra_high(void)	{ asm volatile("or 7,7,7");	}
static inline void smt_very_low(void)	{ asm volatile("or 31,31,31");	}
static inline void smt_lowest(void)	{ smt_low(); smt_very_low();	}

#ifndef __TEST__


/*
 * SPR access functions
 */

static inline unsigned long mfmsr(void)
{
	unsigned long val;

	asm volatile("mfmsr %0" : "=r"(val) : : "memory");
	return val;
}

static inline void mtmsr(unsigned long val)
{
	asm volatile("mtmsr %0" : : "r"(val) : "memory");
}

static inline void mtmsrd(unsigned long val, int l)
{
	asm volatile("mtmsrd %0,%1" : : "r"(val), "i"(l) : "memory");
}

static inline __attribute__((always_inline))
unsigned long mfspr(const unsigned int spr)
{
	unsigned long val;

	asm volatile("mfspr %0,%1" : "=r"(val) : "i"(spr) : "memory");
	return val;
}

static inline __attribute__((always_inline))
void mtspr(const unsigned int spr, unsigned long val)
{
	asm volatile("mtspr %0,%1" : : "i"(spr), "r"(val) : "memory");
}

/* Helpers for special sequences needed by some registers */
extern void set_hid0(unsigned long hid0);
extern void trigger_attn(void);

/*
 * Barriers
 */

static inline void eieio(void)
{
	asm volatile("eieio" : : : "memory");
}

static inline void sync(void)
{
	asm volatile("sync" : : : "memory");
}

static inline void lwsync(void)
{
	asm volatile("lwsync" : : : "memory");
}

static inline void isync(void)
{
	asm volatile("isync" : : : "memory");
}

static inline void mb(void)
{
	asm volatile("sync" : : : "memory");
}

/*
 * Cache sync
 */
static inline void sync_icache(void)
{
	asm volatile("sync; icbi 0,%0; sync; isync" : : "r" (0) : "memory");
}

/*
 * Doorbells
 */
static inline void msgclr(void)
{
	uint64_t rb = (0x05 << (63-36));
	asm volatile("msgclr %0" : : "r"(rb));
}

static inline void p9_dbell_receive(void)
{
	uint64_t rb = (0x05 << (63-36));
	/* msgclr ; msgsync ; lwsync */
	asm volatile("msgclr %0 ; .long 0x7c0006ec ; lwsync" : : "r"(rb));
}

static inline void p9_dbell_send(uint32_t pir)
{
	uint64_t rb = (0x05 << (63-36)) | pir;
	asm volatile("sync ; msgsnd %0" : : "r"(rb));
}

/*
 * Byteswap load/stores
 */

static inline uint16_t ld_le16(const uint16_t *addr)
{
	uint16_t val;
	asm volatile("lhbrx %0,0,%1" : "=r"(val) : "r"(addr), "m"(*addr));
	return val;
}

static inline uint32_t ld_le32(const uint32_t *addr)
{
	uint32_t val;
	asm volatile("lwbrx %0,0,%1" : "=r"(val) : "r"(addr), "m"(*addr));
	return val;
}

static inline void st_le16(uint16_t *addr, uint16_t val)
{
	asm volatile("sthbrx %0,0,%1" : : "r"(val), "r"(addr), "m"(*addr));
}

static inline void st_le32(uint32_t *addr, uint32_t val)
{
	asm volatile("stwbrx %0,0,%1" : : "r"(val), "r"(addr), "m"(*addr));
}

#endif /* __TEST__ */

#endif /* __ASSEMBLY__ */

#endif /* __PROCESSOR_H */
