/*
 * xtensa/config/core-isa.h -- HAL definitions that are dependent on Xtensa
 *				processor CORE configuration
 *
 *  See <xtensa/config/core.h>, which includes this file, for more details.
 */

/* Xtensa processor core configuration information.

   Copyright (c) 1999-2019 Tensilica Inc.

   Permission is hereby granted, free of charge, to any person obtaining
   a copy of this software and associated documentation files (the
   "Software"), to deal in the Software without restriction, including
   without limitation the rights to use, copy, modify, merge, publish,
   distribute, sublicense, and/or sell copies of the Software, and to
   permit persons to whom the Software is furnished to do so, subject to
   the following conditions:

   The above copyright notice and this permission notice shall be included
   in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
   IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
   CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
   TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.  */

#ifndef XTENSA_CORE_TEST_MMUHIFI_C3_CORE_ISA_H
#define XTENSA_CORE_TEST_MMUHIFI_C3_CORE_ISA_H


/****************************************************************************
	    Parameters Useful for Any Code, USER or PRIVILEGED
 ****************************************************************************/

/*
 *  Note:  Macros of the form XCHAL_HAVE_*** have a value of 1 if the option is
 *  configured, and a value of 0 otherwise.  These macros are always defined.
 */


/*----------------------------------------------------------------------
				ISA
  ----------------------------------------------------------------------*/

#define XCHAL_HAVE_BE			0	/* big-endian byte ordering */
#define XCHAL_HAVE_WINDOWED		1	/* windowed registers option */
#define XCHAL_NUM_AREGS			32	/* num of physical addr regs */
#define XCHAL_NUM_AREGS_LOG2		5	/* log2(XCHAL_NUM_AREGS) */
#define XCHAL_MAX_INSTRUCTION_SIZE	8	/* max instr bytes (3..8) */
#define XCHAL_HAVE_DEBUG		1	/* debug option */
#define XCHAL_HAVE_DENSITY		1	/* 16-bit instructions */
#define XCHAL_HAVE_LOOPS		1	/* zero-overhead loops */
#define XCHAL_LOOP_BUFFER_SIZE		0	/* zero-ov. loop instr buffer size */
#define XCHAL_HAVE_NSA			1	/* NSA/NSAU instructions */
#define XCHAL_HAVE_MINMAX		1	/* MIN/MAX instructions */
#define XCHAL_HAVE_SEXT			1	/* SEXT instruction */
#define XCHAL_HAVE_CLAMPS		1	/* CLAMPS instruction */
#define XCHAL_HAVE_MUL16		1	/* MUL16S/MUL16U instructions */
#define XCHAL_HAVE_MUL32		1	/* MULL instruction */
#define XCHAL_HAVE_MUL32_HIGH		0	/* MULUH/MULSH instructions */
#define XCHAL_HAVE_DIV32		0	/* QUOS/QUOU/REMS/REMU instructions */
#define XCHAL_HAVE_L32R			1	/* L32R instruction */
#define XCHAL_HAVE_ABSOLUTE_LITERALS	1	/* non-PC-rel (extended) L32R */
#define XCHAL_HAVE_CONST16		0	/* CONST16 instruction */
#define XCHAL_HAVE_ADDX			1	/* ADDX#/SUBX# instructions */
#define XCHAL_HAVE_WIDE_BRANCHES	0	/* B*.W18 or B*.W15 instr's */
#define XCHAL_HAVE_PREDICTED_BRANCHES	0	/* B[EQ/EQZ/NE/NEZ]T instr's */
#define XCHAL_HAVE_CALL4AND12		1	/* (obsolete option) */
#define XCHAL_HAVE_ABS			1	/* ABS instruction */
/*#define XCHAL_HAVE_POPC		0*/	/* POPC instruction */
/*#define XCHAL_HAVE_CRC		0*/	/* CRC instruction */
#define XCHAL_HAVE_RELEASE_SYNC		1	/* L32AI/S32RI instructions */
#define XCHAL_HAVE_S32C1I		1	/* S32C1I instruction */
#define XCHAL_HAVE_SPECULATION		0	/* speculation */
#define XCHAL_HAVE_FULL_RESET		1	/* all regs/state reset */
#define XCHAL_NUM_CONTEXTS		1	/* */
#define XCHAL_NUM_MISC_REGS		2	/* num of scratch regs (0..4) */
#define XCHAL_HAVE_TAP_MASTER		0	/* JTAG TAP control instr's */
#define XCHAL_HAVE_PRID			1	/* processor ID register */
#define XCHAL_HAVE_EXTERN_REGS		1	/* WER/RER instructions */
#define XCHAL_HAVE_MX			1	/* MX core (Tensilica internal) */
#define XCHAL_HAVE_MP_INTERRUPTS	1	/* interrupt distributor port */
#define XCHAL_HAVE_MP_RUNSTALL		1	/* core RunStall control port */
#define XCHAL_HAVE_PSO			0	/* Power Shut-Off */
#define XCHAL_HAVE_PSO_CDM		0	/* core/debug/mem pwr domains */
#define XCHAL_HAVE_PSO_FULL_RETENTION	0	/* all regs preserved on PSO */
#define XCHAL_HAVE_THREADPTR		1	/* THREADPTR register */
#define XCHAL_HAVE_BOOLEANS		1	/* boolean registers */
#define XCHAL_HAVE_CP			1	/* CPENABLE reg (coprocessor) */
#define XCHAL_CP_MAXCFG			2	/* max allowed cp id plus one */
#define XCHAL_HAVE_MAC16		0	/* MAC16 package */
#define XCHAL_HAVE_VECTORFPU2005	0	/* vector floating-point pkg */
#define XCHAL_HAVE_FP			0	/* single prec floating point */
#define XCHAL_HAVE_FP_DIV		0	/* FP with DIV instructions */
#define XCHAL_HAVE_FP_RECIP		0	/* FP with RECIP instructions */
#define XCHAL_HAVE_FP_SQRT		0	/* FP with SQRT instructions */
#define XCHAL_HAVE_FP_RSQRT		0	/* FP with RSQRT instructions */
#define XCHAL_HAVE_DFP			0	/* double precision FP pkg */
#define XCHAL_HAVE_DFP_DIV		0	/* DFP with DIV instructions */
#define XCHAL_HAVE_DFP_RECIP		0	/* DFP with RECIP instructions*/
#define XCHAL_HAVE_DFP_SQRT		0	/* DFP with SQRT instructions */
#define XCHAL_HAVE_DFP_RSQRT		0	/* DFP with RSQRT instructions*/
#define XCHAL_HAVE_DFP_accel		0	/* double precision FP acceleration pkg */
#define XCHAL_HAVE_VECTRA1		0	/* Vectra I  pkg */
#define XCHAL_HAVE_VECTRALX		0	/* Vectra LX pkg */
#define XCHAL_HAVE_HIFIPRO		0	/* HiFiPro Audio Engine pkg */
#define XCHAL_HAVE_HIFI3		0	/* HiFi3 Audio Engine pkg */
#define XCHAL_HAVE_HIFI2		1	/* HiFi2 Audio Engine pkg */
#define XCHAL_HAVE_HIFI2EP		0	/* HiFi2EP */
#define XCHAL_HAVE_HIFI_MINI		0	
#define XCHAL_HAVE_CONNXD2		0	/* ConnX D2 pkg */
#define XCHAL_HAVE_BBE16		0	/* ConnX BBE16 pkg */
#define XCHAL_HAVE_BBE16_RSQRT		0	/* BBE16 & vector recip sqrt */
#define XCHAL_HAVE_BBE16_VECDIV		0	/* BBE16 & vector divide */
#define XCHAL_HAVE_BBE16_DESPREAD	0	/* BBE16 & despread */
#define XCHAL_HAVE_BBENEP		0	/* ConnX BBENEP pkgs */
#define XCHAL_HAVE_BSP3			0	/* ConnX BSP3 pkg */
#define XCHAL_HAVE_BSP3_TRANSPOSE	0	/* BSP3 & transpose32x32 */
#define XCHAL_HAVE_SSP16		0	/* ConnX SSP16 pkg */
#define XCHAL_HAVE_SSP16_VITERBI	0	/* SSP16 & viterbi */
#define XCHAL_HAVE_TURBO16		0	/* ConnX Turbo16 pkg */
#define XCHAL_HAVE_BBP16		0	/* ConnX BBP16 pkg */
#define XCHAL_HAVE_FLIX3		0	/* basic 3-way FLIX option */


/*----------------------------------------------------------------------
				MISC
  ----------------------------------------------------------------------*/

#define XCHAL_NUM_LOADSTORE_UNITS	1	/* load/store units */
#define XCHAL_NUM_WRITEBUFFER_ENTRIES	8	/* size of write buffer */
#define XCHAL_INST_FETCH_WIDTH		8	/* instr-fetch width in bytes */
#define XCHAL_DATA_WIDTH		8	/* data width in bytes */
#define XCHAL_DATA_PIPE_DELAY		1	/* d-side pipeline delay
						   (1 = 5-stage, 2 = 7-stage) */
/*  In T1050, applies to selected core load and store instructions (see ISA): */
#define XCHAL_UNALIGNED_LOAD_EXCEPTION	1	/* unaligned loads cause exc. */
#define XCHAL_UNALIGNED_STORE_EXCEPTION	1	/* unaligned stores cause exc.*/
#define XCHAL_UNALIGNED_LOAD_HW		0	/* unaligned loads work in hw */
#define XCHAL_UNALIGNED_STORE_HW	0	/* unaligned stores work in hw*/

#define XCHAL_SW_VERSION		1000006	/* sw version of this header */

#define XCHAL_CORE_ID			"test_mmuhifi_c3"	/* alphanum core name
						   (CoreID) set in the Xtensa
						   Processor Generator */

#define XCHAL_BUILD_UNIQUE_ID		0x00005A6A	/* 22-bit sw build ID */

/*
 *  These definitions describe the hardware targeted by this software.
 */
#define XCHAL_HW_CONFIGID0		0xC1B3CBFE	/* ConfigID hi 32 bits*/
#define XCHAL_HW_CONFIGID1		0x10405A6A	/* ConfigID lo 32 bits*/
#define XCHAL_HW_VERSION_NAME		"LX3.0.0"	/* full version name */
#define XCHAL_HW_VERSION_MAJOR		2300	/* major ver# of targeted hw */
#define XCHAL_HW_VERSION_MINOR		0	/* minor ver# of targeted hw */
#define XCHAL_HW_VERSION		230000	/* major*100+minor */
#define XCHAL_HW_REL_LX3		1
#define XCHAL_HW_REL_LX3_0		1
#define XCHAL_HW_REL_LX3_0_0		1
#define XCHAL_HW_CONFIGID_RELIABLE	1
/*  If software targets a *range* of hardware versions, these are the bounds: */
#define XCHAL_HW_MIN_VERSION_MAJOR	2300	/* major v of earliest tgt hw */
#define XCHAL_HW_MIN_VERSION_MINOR	0	/* minor v of earliest tgt hw */
#define XCHAL_HW_MIN_VERSION		230000	/* earliest targeted hw */
#define XCHAL_HW_MAX_VERSION_MAJOR	2300	/* major v of latest tgt hw */
#define XCHAL_HW_MAX_VERSION_MINOR	0	/* minor v of latest tgt hw */
#define XCHAL_HW_MAX_VERSION		230000	/* latest targeted hw */


/*----------------------------------------------------------------------
				CACHE
  ----------------------------------------------------------------------*/

#define XCHAL_ICACHE_LINESIZE		32	/* I-cache line size in bytes */
#define XCHAL_DCACHE_LINESIZE		32	/* D-cache line size in bytes */
#define XCHAL_ICACHE_LINEWIDTH		5	/* log2(I line size in bytes) */
#define XCHAL_DCACHE_LINEWIDTH		5	/* log2(D line size in bytes) */

#define XCHAL_ICACHE_SIZE		16384	/* I-cache size in bytes or 0 */
#define XCHAL_DCACHE_SIZE		16384	/* D-cache size in bytes or 0 */

#define XCHAL_DCACHE_IS_WRITEBACK	1	/* writeback feature */
#define XCHAL_DCACHE_IS_COHERENT	1	/* MP coherence feature */

#define XCHAL_HAVE_PREFETCH		0	/* PREFCTL register */
#define XCHAL_HAVE_PREFETCH_L1		0	/* prefetch to L1 dcache */
#define XCHAL_PREFETCH_CASTOUT_LINES	0	/* dcache pref. castout bufsz */




/****************************************************************************
    Parameters Useful for PRIVILEGED (Supervisory or Non-Virtualized) Code
 ****************************************************************************/


#ifndef XTENSA_HAL_NON_PRIVILEGED_ONLY

/*----------------------------------------------------------------------
				CACHE
  ----------------------------------------------------------------------*/

#define XCHAL_HAVE_PIF			1	/* any outbound PIF present */

/*  If present, cache size in bytes == (ways * 2^(linewidth + setwidth)).  */

/*  Number of cache sets in log2(lines per way):  */
#define XCHAL_ICACHE_SETWIDTH		8
#define XCHAL_DCACHE_SETWIDTH		8

/*  Cache set associativity (number of ways):  */
#define XCHAL_ICACHE_WAYS		2
#define XCHAL_DCACHE_WAYS		2

/*  Cache features:  */
#define XCHAL_ICACHE_LINE_LOCKABLE	0
#define XCHAL_DCACHE_LINE_LOCKABLE	0
#define XCHAL_ICACHE_ECC_PARITY		0
#define XCHAL_DCACHE_ECC_PARITY		0

/*  Cache access size in bytes (affects operation of SICW instruction):  */
#define XCHAL_ICACHE_ACCESS_SIZE	8
#define XCHAL_DCACHE_ACCESS_SIZE	8

#define XCHAL_DCACHE_BANKS		1	/* number of banks */

/*  Number of encoded cache attr bits (see <xtensa/hal.h> for decoded bits):  */
#define XCHAL_CA_BITS			4


/*----------------------------------------------------------------------
			INTERNAL I/D RAM/ROMs and XLMI
  ----------------------------------------------------------------------*/

#define XCHAL_NUM_INSTROM		0	/* number of core instr. ROMs */
#define XCHAL_NUM_INSTRAM		0	/* number of core instr. RAMs */
#define XCHAL_NUM_DATAROM		0	/* number of core data ROMs */
#define XCHAL_NUM_DATARAM		0	/* number of core data RAMs */
#define XCHAL_NUM_URAM			0	/* number of core unified RAMs*/
#define XCHAL_NUM_XLMI			0	/* number of core XLMI ports */

#define XCHAL_HAVE_IMEM_LOADSTORE	1	/* can load/store to IROM/IRAM*/


/*----------------------------------------------------------------------
			INTERRUPTS and TIMERS
  ----------------------------------------------------------------------*/

#define XCHAL_HAVE_INTERRUPTS		1	/* interrupt option */
#define XCHAL_HAVE_HIGHPRI_INTERRUPTS	1	/* med/high-pri. interrupts */
#define XCHAL_HAVE_NMI			0	/* non-maskable interrupt */
#define XCHAL_HAVE_CCOUNT		1	/* CCOUNT reg. (timer option) */
#define XCHAL_NUM_TIMERS		2	/* number of CCOMPAREn regs */
#define XCHAL_NUM_INTERRUPTS		12	/* number of interrupts */
#define XCHAL_NUM_INTERRUPTS_LOG2	4	/* ceil(log2(NUM_INTERRUPTS)) */
#define XCHAL_NUM_EXTINTERRUPTS		9	/* num of external interrupts */
#define XCHAL_NUM_INTLEVELS		2	/* number of interrupt levels
						   (not including level zero) */
#define XCHAL_EXCM_LEVEL		1	/* level masked by PS.EXCM */
	/* (always 1 in XEA1; levels 2 .. EXCM_LEVEL are "medium priority") */

/*  Masks of interrupts at each interrupt level:  */
#define XCHAL_INTLEVEL1_MASK		0x00000FFF
#define XCHAL_INTLEVEL2_MASK		0x00000000
#define XCHAL_INTLEVEL3_MASK		0x00000000
#define XCHAL_INTLEVEL4_MASK		0x00000000
#define XCHAL_INTLEVEL5_MASK		0x00000000
#define XCHAL_INTLEVEL6_MASK		0x00000000
#define XCHAL_INTLEVEL7_MASK		0x00000000

/*  Masks of interrupts at each range 1..n of interrupt levels:  */
#define XCHAL_INTLEVEL1_ANDBELOW_MASK	0x00000FFF
#define XCHAL_INTLEVEL2_ANDBELOW_MASK	0x00000FFF
#define XCHAL_INTLEVEL3_ANDBELOW_MASK	0x00000FFF
#define XCHAL_INTLEVEL4_ANDBELOW_MASK	0x00000FFF
#define XCHAL_INTLEVEL5_ANDBELOW_MASK	0x00000FFF
#define XCHAL_INTLEVEL6_ANDBELOW_MASK	0x00000FFF
#define XCHAL_INTLEVEL7_ANDBELOW_MASK	0x00000FFF

/*  Level of each interrupt:  */
#define XCHAL_INT0_LEVEL		1
#define XCHAL_INT1_LEVEL		1
#define XCHAL_INT2_LEVEL		1
#define XCHAL_INT3_LEVEL		1
#define XCHAL_INT4_LEVEL		1
#define XCHAL_INT5_LEVEL		1
#define XCHAL_INT6_LEVEL		1
#define XCHAL_INT7_LEVEL		1
#define XCHAL_INT8_LEVEL		1
#define XCHAL_INT9_LEVEL		1
#define XCHAL_INT10_LEVEL		1
#define XCHAL_INT11_LEVEL		1
#define XCHAL_DEBUGLEVEL		2	/* debug interrupt level */
#define XCHAL_HAVE_DEBUG_EXTERN_INT	1	/* OCD external db interrupt */

/*  Type of each interrupt:  */
#define XCHAL_INT0_TYPE 	XTHAL_INTTYPE_EXTERN_LEVEL
#define XCHAL_INT1_TYPE 	XTHAL_INTTYPE_EXTERN_LEVEL
#define XCHAL_INT2_TYPE 	XTHAL_INTTYPE_EXTERN_EDGE
#define XCHAL_INT3_TYPE 	XTHAL_INTTYPE_EXTERN_LEVEL
#define XCHAL_INT4_TYPE 	XTHAL_INTTYPE_EXTERN_LEVEL
#define XCHAL_INT5_TYPE 	XTHAL_INTTYPE_EXTERN_LEVEL
#define XCHAL_INT6_TYPE 	XTHAL_INTTYPE_TIMER
#define XCHAL_INT7_TYPE 	XTHAL_INTTYPE_SOFTWARE
#define XCHAL_INT8_TYPE 	XTHAL_INTTYPE_TIMER
#define XCHAL_INT9_TYPE 	XTHAL_INTTYPE_EXTERN_LEVEL
#define XCHAL_INT10_TYPE 	XTHAL_INTTYPE_EXTERN_LEVEL
#define XCHAL_INT11_TYPE 	XTHAL_INTTYPE_EXTERN_LEVEL

/*  Masks of interrupts for each type of interrupt:  */
#define XCHAL_INTTYPE_MASK_UNCONFIGURED	0xFFFFF000
#define XCHAL_INTTYPE_MASK_SOFTWARE	0x00000080
#define XCHAL_INTTYPE_MASK_EXTERN_EDGE	0x00000004
#define XCHAL_INTTYPE_MASK_EXTERN_LEVEL	0x00000E3B
#define XCHAL_INTTYPE_MASK_TIMER	0x00000140
#define XCHAL_INTTYPE_MASK_NMI		0x00000000
#define XCHAL_INTTYPE_MASK_WRITE_ERROR	0x00000000
#define XCHAL_INTTYPE_MASK_PROFILING	0x00000000

/*  Interrupt numbers assigned to specific interrupt sources:  */
#define XCHAL_TIMER0_INTERRUPT		6	/* CCOMPARE0 */
#define XCHAL_TIMER1_INTERRUPT		8	/* CCOMPARE1 */
#define XCHAL_TIMER2_INTERRUPT		XTHAL_TIMER_UNCONFIGURED
#define XCHAL_TIMER3_INTERRUPT		XTHAL_TIMER_UNCONFIGURED

/*  Interrupt numbers for levels at which only one interrupt is configured:  */
/*  (There are many interrupts each at level(s) 1.)  */


/*
 *  External interrupt mapping.
 *  These macros describe how Xtensa processor interrupt numbers
 *  (as numbered internally, eg. in INTERRUPT and INTENABLE registers)
 *  map to external BInterrupt<n> pins, for those interrupts
 *  configured as external (level-triggered, edge-triggered, or NMI).
 *  See the Xtensa processor databook for more details.
 */

/*  Core interrupt numbers mapped to each EXTERNAL BInterrupt pin number:  */
#define XCHAL_EXTINT0_NUM		0	/* (intlevel 1) */
#define XCHAL_EXTINT1_NUM		1	/* (intlevel 1) */
#define XCHAL_EXTINT2_NUM		2	/* (intlevel 1) */
#define XCHAL_EXTINT3_NUM		3	/* (intlevel 1) */
#define XCHAL_EXTINT4_NUM		4	/* (intlevel 1) */
#define XCHAL_EXTINT5_NUM		5	/* (intlevel 1) */
#define XCHAL_EXTINT6_NUM		9	/* (intlevel 1) */
#define XCHAL_EXTINT7_NUM		10	/* (intlevel 1) */
#define XCHAL_EXTINT8_NUM		11	/* (intlevel 1) */
/*  EXTERNAL BInterrupt pin numbers mapped to each core interrupt number:  */
#define XCHAL_INT0_EXTNUM		0	/* (intlevel 1) */
#define XCHAL_INT1_EXTNUM		1	/* (intlevel 1) */
#define XCHAL_INT2_EXTNUM		2	/* (intlevel 1) */
#define XCHAL_INT3_EXTNUM		3	/* (intlevel 1) */
#define XCHAL_INT4_EXTNUM		4	/* (intlevel 1) */
#define XCHAL_INT5_EXTNUM		5	/* (intlevel 1) */
#define XCHAL_INT9_EXTNUM		6	/* (intlevel 1) */
#define XCHAL_INT10_EXTNUM		7	/* (intlevel 1) */
#define XCHAL_INT11_EXTNUM		8	/* (intlevel 1) */


/*----------------------------------------------------------------------
			EXCEPTIONS and VECTORS
  ----------------------------------------------------------------------*/

#define XCHAL_XEA_VERSION		2	/* Xtensa Exception Architecture
						   number: 1 == XEA1 (old)
							   2 == XEA2 (new)
							   0 == XEAX (extern) or TX */
#define XCHAL_HAVE_XEA1			0	/* Exception Architecture 1 */
#define XCHAL_HAVE_XEA2			1	/* Exception Architecture 2 */
#define XCHAL_HAVE_XEAX			0	/* External Exception Arch. */
#define XCHAL_HAVE_EXCEPTIONS		1	/* exception option */
#define XCHAL_HAVE_HALT			0	/* halt architecture option */
#define XCHAL_HAVE_BOOTLOADER		0	/* boot loader (for TX) */
#define XCHAL_HAVE_MEM_ECC_PARITY	0	/* local memory ECC/parity */
#define XCHAL_HAVE_VECTOR_SELECT	1	/* relocatable vectors */
#define XCHAL_HAVE_VECBASE		1	/* relocatable vectors */
#define XCHAL_VECBASE_RESET_VADDR	0xD0000000  /* VECBASE reset value */
#define XCHAL_VECBASE_RESET_PADDR	0x00000000
#define XCHAL_RESET_VECBASE_OVERLAP	0

#define XCHAL_RESET_VECTOR0_VADDR	0xFE000000
#define XCHAL_RESET_VECTOR0_PADDR	0xFE000000
#define XCHAL_RESET_VECTOR1_VADDR	0xD8000500
#define XCHAL_RESET_VECTOR1_PADDR	0x00000500
#define XCHAL_RESET_VECTOR_VADDR	0xFE000000
#define XCHAL_RESET_VECTOR_PADDR	0xFE000000
#define XCHAL_USER_VECOFS		0x00000340
#define XCHAL_USER_VECTOR_VADDR		0xD0000340
#define XCHAL_USER_VECTOR_PADDR		0x00000340
#define XCHAL_KERNEL_VECOFS		0x00000300
#define XCHAL_KERNEL_VECTOR_VADDR	0xD0000300
#define XCHAL_KERNEL_VECTOR_PADDR	0x00000300
#define XCHAL_DOUBLEEXC_VECOFS		0x000003C0
#define XCHAL_DOUBLEEXC_VECTOR_VADDR	0xD00003C0
#define XCHAL_DOUBLEEXC_VECTOR_PADDR	0x000003C0
#define XCHAL_WINDOW_OF4_VECOFS		0x00000000
#define XCHAL_WINDOW_UF4_VECOFS		0x00000040
#define XCHAL_WINDOW_OF8_VECOFS		0x00000080
#define XCHAL_WINDOW_UF8_VECOFS		0x000000C0
#define XCHAL_WINDOW_OF12_VECOFS	0x00000100
#define XCHAL_WINDOW_UF12_VECOFS	0x00000140
#define XCHAL_WINDOW_VECTORS_VADDR	0xD0000000
#define XCHAL_WINDOW_VECTORS_PADDR	0x00000000
#define XCHAL_INTLEVEL2_VECOFS		0x00000280
#define XCHAL_INTLEVEL2_VECTOR_VADDR	0xD0000280
#define XCHAL_INTLEVEL2_VECTOR_PADDR	0x00000280
#define XCHAL_DEBUG_VECOFS		XCHAL_INTLEVEL2_VECOFS
#define XCHAL_DEBUG_VECTOR_VADDR	XCHAL_INTLEVEL2_VECTOR_VADDR
#define XCHAL_DEBUG_VECTOR_PADDR	XCHAL_INTLEVEL2_VECTOR_PADDR


/*----------------------------------------------------------------------
				DEBUG MODULE
  ----------------------------------------------------------------------*/

/*  Misc  */
#define XCHAL_HAVE_DEBUG_ERI		0	/* ERI to debug module */
#define XCHAL_HAVE_DEBUG_APB		0	/* APB to debug module */
#define XCHAL_HAVE_DEBUG_JTAG		0	/* JTAG to debug module */

/*  On-Chip Debug (OCD)  */
#define XCHAL_HAVE_OCD			1	/* OnChipDebug option */
#define XCHAL_NUM_IBREAK		0	/* number of IBREAKn regs */
#define XCHAL_NUM_DBREAK		0	/* number of DBREAKn regs */
#define XCHAL_HAVE_OCD_DIR_ARRAY	0	/* faster OCD option (to LX4) */
#define XCHAL_HAVE_OCD_LS32DDR		0	/* L32DDR/S32DDR (faster OCD) */

/*  TRAX (in core)  */
#define XCHAL_HAVE_TRAX			0	/* TRAX in debug module */
#define XCHAL_TRAX_MEM_SIZE		0	/* TRAX memory size in bytes */
#define XCHAL_TRAX_MEM_SHAREABLE	0	/* start/end regs; ready sig. */
#define XCHAL_TRAX_ATB_WIDTH		0	/* ATB width (bits), 0=no ATB */
#define XCHAL_TRAX_TIME_WIDTH		0	/* timestamp bitwidth, 0=none */

/*  Perf counters  */
#define XCHAL_NUM_PERF_COUNTERS		0	/* performance counters */


/*----------------------------------------------------------------------
				MMU
  ----------------------------------------------------------------------*/

/*  See core-matmap.h header file for more details.  */

#define XCHAL_HAVE_TLBS			1	/* inverse of HAVE_CACHEATTR */
#define XCHAL_HAVE_SPANNING_WAY		0	/* one way maps I+D 4GB vaddr */
#define XCHAL_HAVE_IDENTITY_MAP		0	/* vaddr == paddr always */
#define XCHAL_HAVE_CACHEATTR		0	/* CACHEATTR register present */
#define XCHAL_HAVE_MIMIC_CACHEATTR	0	/* region protection */
#define XCHAL_HAVE_XLT_CACHEATTR	0	/* region prot. w/translation */
#define XCHAL_HAVE_PTP_MMU		1	/* full MMU (with page table
						   [autorefill] and protection)
						   usable for an MMU-based OS */
/*  If none of the above last 4 are set, it's a custom TLB configuration.  */
#define XCHAL_ITLB_ARF_ENTRIES_LOG2	2	/* log2(autorefill way size) */
#define XCHAL_DTLB_ARF_ENTRIES_LOG2	2	/* log2(autorefill way size) */

#define XCHAL_MMU_ASID_BITS		8	/* number of bits in ASIDs */
#define XCHAL_MMU_RINGS			4	/* number of rings (1..4) */
#define XCHAL_MMU_RING_BITS		2	/* num of bits in RING field */

#endif /* !XTENSA_HAL_NON_PRIVILEGED_ONLY */


#endif /* XTENSA_CORE_TEST_MMUHIFI_C3_CORE_ISA_H */
