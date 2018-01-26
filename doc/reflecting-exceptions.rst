============================
Reflecting exceptions to HV
============================

.. contents::
        :depth: 3

.. sectnum::
        :depth: 3

Overview
========

In general Ultravisor handles a few exceptions internally and reflectes
all hcalls and most other exceptions from the SVM to the Hypervisor.

UV operates between two boundaries/transitions: SVM/UV and UV/HV. It
is important to for UV to  prevent sensitive information such as
instruction addresses, data values, instruction counts (which can
apparently be used to guess encryption/hasing algorithms?) etc of
the UV and SVM from being visible to the HV.

The process of preventing leaks involves several steps:

        - SVM Exit: On transitioning from SVM to UV, save the SVM state of
          most registers. warn f any insecure features in the system (such
          as EBB) have been enabled in the SVM. check_regs_on_svm_exit().

        - HV Entry: Before transitiong from UV to HV, save the UV state of
          registers and then clear/mask sensitive registers.
          eg: fixup_regs_for_hv_entry().

        - HV Exit: On transitioning from HV to UV, restore the UV state of
          all registers. Some registers like Instruction Counter, need to
          be updated rather than restored. Warn if HV tweaked any sensitive
          registers unexpectedly. fixup_regs_on_hv_exit().

        - SVM Entry: Before transitioning from UV to SVM, restore the
          state relevant to the guest AND ensure insecure features are
          disabled.  fixup_regs_for_svm_entry().

The sets of registers saved/restored across the two boundaries are not
identical. Some registers may only need to be saved/restored across one
but not the other. Further, some registers need to be cleared/masked
across the UV/HV boundary but must be restored across the UV/SVM boundary.

All registers in `struct stack_frame` are in general saved and restored
across both boundaries. But for space/time reasons we dont want to add
all registers to the stack_frame. Instead, we handle the other registers
individually across the 4 transitions.

Actions on registers are classified as:

        * Ignore - dont have to do anything across the boundary eg:
          no sensitive information.

        * Save and Clear - Save the register's state and clear it (or
          put in a random).

        * Restore

        * Initialize - explicitly initialize each of the bit fields.

        * Some special handling (eg: decrementer, IC)

MPIPL
=====

Memory Preserving Initial Program Load (MPIPL) occurs when either the
Hypervisor or Ultravisor decides that there is a serious issue that
requires a dump. All of the cores are stopped and their state is moved
to normal memory so that it can be dumped on the next IPL.  Prior to the
dump, the Ultravisor state has to be processed to prevent leaking sensitive
information. The dump will not include memory of an SVM or VM.  It will
only include information for the Hypervisor and Ultravisor.

Memory
-------
Secure memory should be handled as follows for MPIPL:

        - No SVM memory should be included in the dump (Ultravisor to enforce).

        - No secure memory containing seeds or keys should be included
          (Ultravisor to enforce).

        - Exclude Ultravisor memory where SVM registers are saved as part of
          U-call or H-call processing (Ultravisor to enforce).

        - Exclude all memory areas used by Ultravisor cryptographic code as
          working areas or set-up areas.


Registers
---------
MPIPL register handling is determined by what is running on the thread at
the time of the dump.  There are four cases depending on whether the thread
is running:

        - a VM,

        - an SVM

        - the hypervisor,

        - the  Ultravisor.


Ultravisor
----------
The stack pointer (R1) should be dumped. All other GPRs should be cleared.
SPRs must be handled in a manner similar to the transition between the UV and
the HV. If the core is in the UV then the registers that may contain sensitive
data must be cleared.  However, the following registers should appear in the
dump to aid debugging: SMFCTRL, MSR, NIP, LR, CFAR, HEIR, HDAR HDSISR, SRR0,
SRR1, USRR0, USRR1, HSRR0 and HSRR1. An MPIPL entry has been added to each
register below to indicate what action should be taken when the core is
running in Ultravisor mode.

SVM or VM
---------
All GPRs and SPRs should be cleared and none should be dumped.

Hypervisor
----------
No change to handling of hypervisor registers.

Register Guidance
=================
Following notes describe actions needed for a register, if any, across either
boundary and for MPIPL.

The information here (and resulting implementation in code) is based
on extensive discussions with and input from Ramachandra Pai,
Michael Anderson, Paul Mackerras, Guerney Hunt, Debapriya Chatterjee.

AMOR
----
    Authority Mask Override Register. Pg 1011 ISA.

    Keys only supported for Hash Page Tables. If keys become active for
    Radix in P10 DD2, then will need to manage AMOR.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

AMR
---
    Authority Mask Register

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Save and Clear
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Clear

ASDR
----
    Access Segment Descriptor Register

    Not accessible to SV or guest. Reflect for relevant interrupts, clear
    otherwise.

    ASDR is set by the hardware on an HV storage interrupt. It should not
    change while UV is executing so we do not have to save/restore it on
    UV/SVM transitions. However if it does change, we want to make sure to
    forward its proper value when reflecting certain exceptions to HV.

    If 100% sure that ASDR does not change while in UV, we could get a
    small performance improvement by not saving/restoring ASDR.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Forward to HV for specific interrupts, clear otherwise.
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Clear

BESCR
-----
    Branch Event Status & Control Register controls and has status of Event
    based branch events.

    We had talked about disabling EBB, TM and other such features in BESCR.
    BESCR seems to be a supervisor "owned" register and we disable EBB
    and other features in HFSCR (for both supervisor and problem state).
    So, don't need to do anything here while entering SVM. Also, this
    register does not have any sensitive information, so can be ignored
    when entering HV also. However, print a warning message if the
    features are enabled on entry into UV (from either SVM or HV).

    * SVM/UV: Warn if EBB or PMU-based EBB, TM etc were enabled.

    * UV/SVM: Ignore.  EBB, TM etc are disabled in HFSCR. Don't need
              to disable them here.

    * UV/HV:  Ignore since there is no sensitive information in this
              register. HV may get a hint if PMEO or EEO bits are set
              but since we disable EBB/PM in SVMs, those bits should
              never be set.

    * HV/UV:  Warn if EBB, TM were enabled by HV but otherwise ignore.
              We disable faciliities in HFSCR before returning to SVM.

    * P9 Status: Done
    * MPIPL-UV:  Ignore

BHRB
----
    Branch History Rolling Buffer Register. ISA pg 1125.

    Reserved Register - according to P9 User Manual.

    We wanted to disable BHRB in SVMs, but later decided against it.
    Instead we now allow BHRB in SVMs and UV and simply clear the BHRB
    when entering HV so no information leaks.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Clear BHRB
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Clear

CFAR
----
    Come From Address Register

    * SVM/UV:    Save SVM's value
    * UV/SVM:    Restore SVM's value
    * UV/HV:     Save UV value and Clear
    * HV/UV:     Restore UV value
    * P9 Status: Done
    * MPIPL-UV:  Ignore, requested for debuging

CIABR
-----
    Completed Instruction Address Breakpoint Register.

    New HCALL to be intercepted/implemented entirely by UV (not reflected
    to HV) to enable/disable debug.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Save and Clear
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Clear

CIR
---
    Chip Info Register.

    HV cannot write register

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

CTR
---
    Count Register

    * SVM/UV:    Save SVM's value
    * UV/SVM:    Restore SVM's value
    * UV/HV:     Save UV's value and Clear
    * HV/UV:     Restore UV's value
    * P9 Status: Done
    * MPIPL-UV:  Clear

CTRL (SPRN 152)
---------------
    Control Register. ISA pg 962.

    HV can only read, but not modify. SV can only read bit 63 which indicates
    whether OS is doing useful work. No sensitive information.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

CTRL_RU
-------
    Control Register. See CTRL.

DAR
---
    Data Address Register.

    Forward value to HV for specific interrupts and save, clear and restore
    otherwise. Value should not change while executing in UV so don't have
    to save/restore across SVM/UV transitions.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore or Save and Clear depending on interrupt.
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Clear

DAWR, DAWRX
-----------
    Data Address Watch Point

    New HCALL to be intercepted/implemented entirely by UV (not reflected
    to HV) to enable/disable debug.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Save and Clear.
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Clear

DEC
---
    Decrementer.

    Save decrementer-expiry value upon entry into UV from SVM. Before
    returning to SVM, recompute the decrementer value based on the
    current time base and saved decrementer-expiry.

    Use guest's time base if we enter UV from guest. Else use HV's
    timebase. Discussed May 23, 2019 conference call.

    * SVM/UV:    Save decrementer-expiry
    * UV/SVM:    Restore decrementer based on new TB value and saved expiry.
    * UV/HV:     Save and set to max value
    * HV/UV:     Ignore
    * P9 Status: Done
    * MIPL:      Ignore

DPDES
-----
    Directed Priv. Doorbell Excp. State. ISA Pg 1127.

    Since we disable doorbells in SVM we can set DPDES to zero in SVMs
    and Ignore when going into HV. (Dicsussed May 23, 2019 conf call)

    * SVM/UV:    Ignore
    * UV/SVM:    Clear register
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

DSCR (SPRN 17)
--------------
    Data Stream Control Register ("Software defined data streams").

    SV cannot read/write register at this SPR number but can use a
    different SPR (see DSCR_RU)

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Save and clear
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Clear

DSCR_RU (SPRN 3)
----------------
    Data Stream Control Register. ISA pg 837.

    Facility Unavailable Interrupt when PR=1 - see DSCR above.

DSISR
-----
    Data Storage Interrupt Register.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Forward to HV on MCE interrupts, save and clear otherwise.
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Clear

EBBHR, EBBRR
------------
    Event Based Branch Handler and Return Register

    EBBRR contains the address of instruction we would execute if an EBB
    event had not occurred. EBBHR contains address of instruction we must
    execute next when an EBB does occur. EBB facility must be disabled in
    SVM and these registers should not contain any useful information. But
    to be sure, save and clear when entering HV and restore upon return.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Save and clear
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Clear

FSCR
----
    Facility Status & Control

    We had talked about disabling EBB and other such features in FSCR.
    FSCR seems to be a supervisor "owned" register and we disable EBB
    and other features in HFSCR (for both supervisor and problem state).
    So, don't need to do anything here while entering SVM. Also, this
    register does not have any sensitive information, so can be Ignored
    when entering HV also. However, print a warning message if the
    features are enabled on entry into UV (from either SVM or HV).

    * SVM/UV:    Warn if EBB is enabled.
    * UV/SVM:    Ignore
    * UV/HV:     Ignore, no sensitive information in register.
    * HV/UV:     Warn if EBB was enabled, otherwise ignore.

    * P9 Status: Done
    * MPIPL-UV:  Ignore

GSR
---
    Group Start Register. ISA pg 970.

    Transaction register. Discussed with Debapriya. Does not work on P9.
    Maybe enabled in P10 DD2. Consider using in P10 DD2 for UV perf
    optimization.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

HDAR
----
    HV Data Address Register.

    SV cannot read/write register.

    HDAR is set by the hardware on an HDSI. It should not change while
    UV is executing so we should not have to save/restore it.  However
    if it does change, we want to make sure to forward its proper value
    when reflecting to HV.

    If 100% sure that HDAR does not change while in UV, we could get a
    small performance improvement by not saving/restoring HDAR.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore or Save and Clear depending on interrupt.
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Ignore, requested for debug

HDEC
----
    HV Decrementer

    Supervisor cannot read/write register and UV does not use this, so
    no sensitive information.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Done
    * P9 Status: Done
    * MPIPL-UV:  Ignore

HDSISR
------
    HV Data Storage Interrupt Register

    HDSISR is set by the hardware on an HDSI. It should not change while
    UV is executing so we should not have to save/restore it on the UV/SVM
    transition. However if it does change, we want to make sure to forward
    its proper value when reflecting to HV.

    If 100% sure that HDSISR does not change while in UV, we could get a
    performance improvement by not saving/restoring HDSISR.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore or Save and Clear depending on interrupt.
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Ignore, requested for debug

HEIR
----
    HV Emulated Instruction Register

    Supervisor cannot read/write register and UV does not use this, but
    since it contains an instruction from the SVM, mask it on HV entry.
    no sensitive information.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Save and Clear
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Ignore, requested for debug

HFSCR
-----
    HV Facility Status and Control Register. ISA pg 1052.

    Disable EBB, TM and other such features when entering SVM. Synthesize
    "Illegal instruction" if we get HV Facility Unavailable exception due
    to SVM trying to use one of the disabled facilities.

    * SVM/UV: Warn if insecure features (EBB,BHRB,TM) are enabled in
              HFSCR. Don't need to save state since we will disable
              faciliities before returning to SVM.

    * UV/SVM: Ensure that insecure features (EBB, BHRB, TM) are disabled
              in HFSCR.

    * UV/HV:  Ignore - since there is no security leak in this register
              itself.

    * HV/UV:  Warn if EBB, BHRB, TM were enabled by HV. Don't need to
              restore state (we didn't save in UV/HV). We will disable
              faciliities before returning to SVM.

    * P9 Status: Pending (see TODO's below).

    * MPIPL-UV:  Ignore

    TODO: We disable the features when entering SVM and discard the HV's
          state of the register. Try to save/restore HV state of HFSCR
          reentering HV later (for a different exception). How does it
          affect other transaction registers (TFHAR, TFIAR etc)

    TODO: Needs revisit/design for fine-grained SMF

    TODO: Abort transaction if TM is enabled on entry into UV from HV.
          (check MSR_TS and MSR_TA bits in active MSR, not usrr1; use
          ta_abort instruction)


HID
---
    HW Implimentation Register 0. Not in ISA?

    SV cannot read/write register.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

HMEER
-----
    HV Maintenance Exception Enable Mask Register

    SV cannot read/write register. UV does not use this so no sensitive
    information.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

HMER
----
    HV Maint. Exception Register. Pg. 1069 of ISA.

    Supervisor cannot read/write register and UV does not use this so no
    sensitive information.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

HRMOR
-----
    HV Real Mode Offset Register.

    Supervisor cannot read/write register and UV does not use this so no
    sensitive information.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

HSPRG0,1
--------
    HV Software Programmable Register.

    Supervisor cannot read/write register and UV does not use this so no
    sensitive information.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

HSRR0
-----
    HV Save/Restore Register.

    Contains the address of the instruction in the SVM where the exception
    occured.

    * SVM/UV:    Save
    * UV/SVM:    Initialize as needed (eg: to synthesize interrupt, return
                 success to SVM etc).
    * UV/HV:     Initialize to enter HV (mask SVM's value).
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Ignore, requested for debug

HSRR1
-----
    HV Save/Restore Register 1

    Contains the machine state of the SVM when the exception occured.

    * SVM/UV:    Ignore
    * UV/SVM:    Initialize as needed (eg: to synthesize interrupt).
    * UV/HV:     Initialize to enter HV (mask SVM's value).
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Ignore, requested for debug

IAMR
----
    Instruction Authority Mask Register.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Save and Clear
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Clear

IC
--
    Instruction Counter. ISA pg 1102.

    We don't want HV to know exact instruction counts in the SVM so
    clear it when entering HV and update (don't restore) it upon return
    from HV. We don't need to save/restore across UV/SVM boundary so no
    entries in stack_frame. Instead when going across UV/HV boundary,
    directly update the live register state. Based on input from
    Debapriya[5].

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Save the IC value and clear.
    * HV/UV:     Restore saved value *and* update it with # of instructions
                 executed in HV.
    * P9 Status: Done
    * MPIPL-UV:  Clear

IMC
---
    In-Memory Collection?

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

L2QOSR
------
    Not in ISA/Kernel. Need documentation.

    SV cannot read/write register.  Confirmed with Debapriya[5].

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore.
    * P9 Status: Done
    * MPIPL-UV:  Ignore

LDBAR
-----
    LD Base Addr Register. Not found in ISA?

    Used with In-Memory Collection (IMC) of Perf. Data. Supervisor cannot
    write. UV privileged when SMF is on. Confirmed with Debapriya[5]

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

LPCR
----
    Logical Partitioning Control Register

    Supervisor cannot read/write register and UV does not use this so no
    sensitive information.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

    TODO: Should we **preserve** values we have on UV_RETURN rather than
           restoring to the value we had at SVM/UV transition?


LPIDR
-----
    Logical Partitioning Id

    Supervisor cannot read/write register and UV does not use this so no
    sensitive information.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Assert if HV changes LPIDR.

    * P9 Status: Done
    * MPIPL-UV:  Ignore
    * TODO:      Does HV have a legitimate need to change LPIDR?
                 If so, should we **preserve** new value from HV we get
                 in UV_RETURN?

LR
--
    Link Register

    * SVM/UV:    Save SVM's value
    * UV/SVM:    Restore SVM's value
    * UV/HV:     Save UV's value and Clear
    * HV/UV:     Restore UV's value
    * P9 Status: Done
    * MPIPL-UV:  Ignore, requested for debug

MMCR0, MMCR0_RU
---------------

    Monitor Mode Control Register 0.

    Used for Performance monitoring. Does HV have legit need to modify/update
    this register?

    For now, disable EBB and performance monitoring in SVMs. HV could
    re-enable these, but we will disable them on every SVM entry.

    * SVM/UV:    Don't need to save when entering UV as we will
                 disable Performance Monitoring SVM.

    * UV/SVM:    Freeze all counters and disable EBB and performance
                 monitoring when entering SVM. Probably not needed since
                 we must anyway disable performance monitoring in HFSCR.

    * UV/HV:     Ignore (no SVM sensitive information in register)

    * HV/UV:     Ignore (no SVM sensitive information in register)

    * P9 Status: Done

    * MPIPL-UV:  Ignore

    * TODO:      Maintain separate states for SVM and HV restore the
                 one you are entering?

    * TODO:      Have a config option maybe in ESM blob to enable
                 performance counters (but NOT BHRB and EBB) for a
                 specific VM - maybe needed for Performance Overhead
                 analysis.

MMCR1, MMCR1_RU
----------------

    Monitor Mode Control Register 1

    Used for Performance monitoring. Contains the actual events to monitor.

    * SVM/UV:    Don't need to save when entering UV as we will
                 disable Performance Monitoring SVM.

    * UV/SVM:    Clear register so no events are loaded in MMCR1.
                 Probably not needed since we must anyway disable
                 performance monitoring in HFSCR.

    * UV/HV:     Ignore (no SVM sensitive information in register)

    * HV/UV:     Ignore (no SVM sensitive information in register)

    * P9 Status: Done

    * MPIPL-UV:  Ignore

    * TODO:      Maintain separate states for SVM and HV restore the
                 one you are entering?

    * TODO:      Have a config option maybe in ESM blob to enable
                 performance counters (but NOT BHRB and EBB) for a
                 specific VM - maybe needed for Performance Overhead
                 analysis.

MMCR2, MMCR2_RU
----------------

    Monitor Mode Control Register 2

    Used for Performance monitoring. Contains the conditions when events
    should be counted/frozen.

    * SVM/UV:    Don't need to save when entering UV as we will
                 disable Performance Monitoring SVM.

    * UV/SVM:    Freeze all conditions so no events are counted in any of
                 the 6 PMCs. Probably not needed since we must disable
                 performance monitoring in HFSCR anyway.

    * UV/HV:     Ignore (no SVM sensitive information in register)

    * HV/UV:     Ignore (no SVM sensitive information in register)

    * P9 Status: Done

    * MPIPL-UV:  Ignore

    * TODO:      Maintain separate states for SVM and HV restore the
                 one you are entering?

    * TODO:      Have a config option maybe in ESM blob to enable
                 performance counters (but NOT BHRB and EBB) for a
                 specific VM - maybe needed for Performance Overhead
                 analysis.

MMCRA, MMCRA_RU
----------------

    Monitor Mode Control Register A.

    Used for Performance monitoring. Controls sampling process by
    choosing options/filters.

    * SVM/UV:    Don't need to save when entering UV as it only
                 contains options/filters for performance monitoring
                 which will be disabled for SVM.

    * UV/SVM:    Clear MMCRA_SAMPLE_ENABLE bit although its probably not
                 strictly necessary since we must disable performance
                 monitoring in HFSCR.

    * UV/HV:     Ignore (no SVM sensitive information in register)

    * HV/UV:     Ignore (no SVM sensitive information in register)

    * P9 Status: Done

    * MPIPL-UV:  Ignore

    * TODO:      Maintain separate states for SVM and HV restore the
                 one you are entering?

    * TODO:      Have a config option maybe in ESM blob to enable
                 performance counters (but NOT BHRB and EBB) for a
                 specific VM - maybe needed for Performance Overhead
                 analysis.

MMCRC
-----
    Monitor Mode Control Register C. Not found in ISA.

    Used for Performance monitoring. HW Team recommends we clear the
    register when entering SVM.

    * SVM/UV:    Ignore
    * UV/SVM:    Clear
    * UV/HV:     Save and Clear
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

MSR
---
    Machine State Register.

    When HV makes an ucall, abort transactions (if any), reset MSR_TS
    and MSR_TA register while in UV.

    * SVM/UV:    Ignore
    * UV/SVM:    Restored as a part of urfid from SRR1.
    * UV/HV:     Initialized as a part of urfid from SRR1/HSRR1
    * HV/UV:     Restore UV state.
    * P9 Status: Done
    * MPIPL-UV:  Ignore, requested for debug

    TODO: aborting transactions

PCR
---
    Processor Compatibility Register

    Supervisor cannot read/write register and UV does not use this so no
    sensitive information.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

PIDR
----
    Process ID Register. ISA pg 962.

    Supervisor cannot read/write register and UV does not use this so no
    sensitive information.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Assert if HV changes PIDR.

    * P9 Status: Done
    * MPIPL-UV:  Ignore
    * TODO:      Does HV have a legitimate need to change LPIDR?
                 If so, should we **preserve** new value from HV we get
                 in UV_RETURN?

PIR
---
    Processor Identification Register

    No one can write to register, so no sensitive information.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

PMCR
----
    Power Management Control Register. Not found in ISA.

    HV and Supervisor cannot read/write register and UV does not use this
    so no sensitive information.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

PMC[1:6]
--------
    Performance Monitoring Counters.

    Used for Perf monitoring. We disable performance monitoring in SVMs
    (in the HFSCR) so these registers should not have any sensitive
    information. Save and clear when entering HV anyway.

    * SVM/UV:    Don't need to save when entering UV as Performance
                 Monitoring is disabled for SVM.

    * UV/SVM:    Don't need to restore as Performance Monitoring is
                 disabled for SVM.

    * UV/HV:     Save and Clear
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Clear

    * TODO:      Maintain separate states for SVM and HV restore the
                 one you are entering?

PMC[1:6]_RU
-----------
    Performance Monitoring Counters. See PMC[1:6].

PMSR
----
    Power Management Status Register. Not found in ISA.

    HV and Supervisor cannot read/write register and UV does not use this
    so no sensitive information.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

PPR
---
    Program Priority Register. ISA pg 963.

    Affects Program Priority but no sensitive information.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Set to "Very Low" priority (0ULL is not valid)
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

PPR32
-----
    Program Priority Register. ISA pg 963.

    Affects Program Priority but no security leak bw SVM and HV? Same
    register as PPR. No change needed (not applicable to 64-bit systems?)

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

PSPB
----
    Problem State Priority Boost

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Save and Clear
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Clear

PSSCR
-----
    Processor Stop Status & Control Register. ISA pg 967.

    Power Saving Level settings. Supervisor cannot write this and UV does
    not use this.  Don't see any sensitive information.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

PSSCR_SU
--------
    Processor Stop Status & Control Register. ISA pg 949.

    See PSSCR.

PTCR
----
    Partition Table Control Register.

    HV and Supervisor cannot read/write register and UV does not use this
    so no sensitive information.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

PURR
----
    Processor Utilization Resource Register

    Opened issue #92 to disable PURR/SPURR for SVM. Check RWMR below if we
    change behavior of PURR/SPURR

    * SVM/UV:    Warn and clear PURR if enabled in LPCR
    * UV/SVM:    Disable PURR/SPURR for SVM.
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

PVR
---
    Processor Version Register

    HV cannot write register.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done.
    * MPIPL-UV:  Ignore

RPR
---
    Relative Priority. ISA Pg 963.

    HV-only register. SVM cannot use it. HV can adjust priority the HW
    thread gets. It cannot tamper with SVM but can slow it down. Ignore.
    Discussed May 23, 2019 conference call.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

RWMR
----
    Registeration Weighting Mode Register. Not in ISA?

    Supervisor cannot write to register and UV does not use this so no
    sensitive information. Like with PURR/SPURR.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore
    * TODO:      Revisit if we change behavior or PURR/SPURR.

SDAR, SDAR_RU
-------------
    Sampled Data Address Register.

    Used for Performance monitoring.

    * SVM/UV:    Don't need to save when entering UV as Performance
                 Monitoring is disabled for SVM.

    * UV/SVM:    Don't need to restore as Performance Monitoring is
                 disabled for SVM.

    * UV/HV:     Save and Clear
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Clear

    * TODO:      Maintain separate states for SVM and HV restore the
                 one you are entering?

SIAR, SIAR_RU
-------------

    Sampled Instruction Address Register.

    Used for Performance monitoring.

    * SVM/UV:    Don't need to save when entering UV as Performance
                 Monitoring is disabled for SVM.

    * UV/SVM:    Don't need to restore as Performance Monitoring is
                 disabled for SVM.

    * UV/HV:     Save and Clear
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Clear

    * TODO:      Maintain separate states for SVM and HV restore the
                 one you are entering?

SIER, SIER_RU
-------------

    Sampled Instruction Event Register

    Used for Performance monitoring.

    * SVM/UV:    Don't need to save when entering UV as Performance
                 Monitoring is disabled for SVM.

    * UV/SVM:    Don't need to restore as Performance Monitoring is
                 disabled for SVM.

    * UV/HV:     Save and Clear
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Clear

    * TODO:      Maintain separate states for SVM and HV restore the
                 one you are entering?

SMFCTRL
-------
    Secure Memory Facility Control Register.

    Only UV can use

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

SPRC
----
    aka SPRG4

    Not in ISA. Platform register. In P9 HV can R/W even with UV. SCOM
    filtering applies - UV should handle these UV already handles SCOMS so
    Ignore (Confirmed with Debapriya)

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

SPRD
----
    aka SPRG5

    Not in ISA. Platform register. In P9 HV can R/W even with UV. SCOM
    filtering applies - Since UV already handles SCOMS so Ignore
    (Confirmed with Debapriya)

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

SPRG3_RU
--------
    Software Programmable SPRs

    HV cannot write register.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

SPRG[0:3]
---------
    Special Purpose Register General.  Clear when entering HV and restore
    upon return. Its possible that we don't need to save/restore across UV/
    SVM boundary since UV does not modify these registers, but we are
    currently saving/restoring here as well.

    * SVM/UV:    Save
    * UV/SVM:    Restore
    * UV/HV:     Save and Clear.
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Clear

SPURR
-----
    Scaled Processor Utilization Resource Register.

    Opened issue #92 to disable PURR/SPURR for SVM. Check RWMR above if we
    change behavior of PURR/SPURR

    * SVM/UV:    Warn and clear SPURR if enabled in LPCR
    * UV/SVM:    Disable PURR/SPURR
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

SRR0
----
    Save/Restore Register 0.

    See Issue #91 Fill/Restore AND allow for Synthesized interrupts

    * SVM/UV:    Save
    * UV/SVM:    Initialize as needed (eg: to synthesize interrupt, return
      success to SVM etc).
    * UV/HV:     Initialize to enter HV (mask SVM's value).
    * HV/UV:     Restore.
    * P9 Status: Done
    * MPIPL-UV:  Ignore, requested for debug

SRR1
----
    Save/Restore Register 1.

    HV uses this know if it must return to UV.

    * SVM/UV:    Ignore
    * UV/SVM:    Initialize as needed (eg: to synthesize interrupt).
    * UV/HV:     Initialize to enter HV (mask SVM's value).
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Ignore, requested for debug

TAR
---
    Target Address Register.

    Contains the address to which a `bctar` instruction would jump.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Save and Clear
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

TB
--
    Time Base

    HV cannot write register.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

TBL
---
    Time Base Lower 32 bits. ISA pg 897, 1097.

    Same physical register as TB. Confirmed with Debapriya[5]

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

TBU
---
    Time Base Upper 32 bits. ISA pg 897, 1097.

    Same physical register as TB. Confirmed with Debapriya[5]

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

TBU40
-----
    Time Base Upper 40 bits.  ISA pg 897, 1097.

    Same physical register as TB. Confirmed with Debapriya[5]

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

TBU_RU
------
    Time Base

    HV cannot write register

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

TEXASR
------
    Transcation Exception And Status Register.  ISA pg 886.

    Contains an address In P10, UV has to disable by updating HFSCR. In P9
    chicken-switch will be off, so UV has to prevent leaks to HV When we get an
    ucall from HV, save its value, put a neutral value in it while in UV.
    Restore its value before returning to HV Confirmed with Debapriya.

    2019-514: Per email discussion with Paul since TM is disabled for all
    SVMs, Ignore this register.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

TEXASRU
-------
    Transcation Exception And Status Upper Register.  ISA pg 886.

    Contains an address In P10, UV has to disable by updating HFSCR. In P9
    chicken-switch will be off, so UV has to prevent leaks to HV When we get an
    ucall from HV, save its value, put a neutral value in it while in UV.
    Restore its value before returning to HV Confirmed with Debapriya.

    2019-514: Per email discussion with Paul since TM is disabled for all
    SVMs, Ignore this register.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

TFHAR
-----
    Transcation Exception And Status Upper Register.  ISA pg 886.

    Contains an address In P10, UV has to disable by updating HFSCR. In P9
    chicken-switch will be off, so UV has to prevent leaks to HV When we get an
    ucall from HV, save its value, put a neutral value in it while in UV.
    Restore its value before returning to HV Confirmed with Debapriya.

    2019-514: Per email discussion with Paul since TM is disabled for all
    SVMs, Ignore this register.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

TFIAR
-----
    Transaction Failure Instruction Address. ISA pg 889.

    Contains an address In P10, UV has to disable by updating HFSCR. In P9
    chicken-switch will be off, so UV has to prevent leaks to HV When we get an
    ucall from HV, save its value, put a neutral value in it while in UV.
    Restore its value before returning to HV Confirmed with Debapriya

    2019-514: Per email discussion with Paul since TM is disabled for all
    SVMs, Ignore this register.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

TFMR
----
    Timer Facility Management Register? ISA pg 897, 1097.

    Confirmed with Debapriya[5] What does changing TB mean to running
    software?

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV   Ignore

TIDR
----
    Thread Id Register. ISA pg 962.

    This is a Supervisor register so mask it on HV entry.

    It is used by coprocessors like NX. Maybe used by GPU/NPU? Revisit
    this for P10 and fine-grained.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Save and Clear
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Clear

TIR
---
    Thread Identification Register.

    SV can read register and HV has to set it. so Ignore

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

TRACE
-----
    Not in ISA? Need documentation.

    Does it become UV privileged when SMF is on? (From Debapriya[5]: UV
    should zero out this register before entering SVM)

    * SVM/UV:    Ignore
    * UV/SVM:    Clear
    * UV/HV:     Save and Clear.
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

TRIG[0:2]
---------
    HV cannot read. Used for HW Bringup, NOP otherwise.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

TSCR
----
    Thread Switch Control Register. Not in ISA? Need documentation.

    Does it become UV privileged when SMF is on? Ignore. Confirmed with
    Debapriya[5]

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done.
    * MPIPL-UV:  Ignore

TTR
---
    Not in ISA? Need documentation.

    Does it become UV privileged when SMF is on? Ignore. Confirmed with
    Debapriya[5].

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

UAMOR
-----
    User Authority Mask Override Register.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Save and Clear
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

UAMR
----
    In ISA as alias for AMR. See AMR.

URMOR
-----
    UV Real Mode Offset Register.

    Only UV can use

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

USPRG0,1
--------
    UV Scratch Registers.

    Only UV can use

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

USRR0,1
-------
    UV Save/Restore Registers.

    Only UV can use

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore, requested for debug

VRSAVE
------
    Vector Register Save/Restore Intended for OS and appliction use.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Save and Clear.
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

VTB
---
    Virtual Time Base Register. ISA pg 1116.

    HV already knows how long the SVM has been running for, so we don't
    need to mask it. Discussed in May 23 2019 Conf call.

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

WORT
----
    Workload Optimization Register- Thread. Not in ISA? Need documentation.

    Ignore. Confirmed with Debapriya[5]

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Ignore
    * HV/UV:     Ignore
    * P9 Status: Done
    * MPIPL-UV:  Ignore

XER
---
    Fixed Point Exception Register

    * SVM/UV:    Ignore
    * UV/SVM:    Ignore
    * UV/HV:     Save and Clear
    * HV/UV:     Restore
    * P9 Status: Done
    * MPIPL-UV:  Ignore
