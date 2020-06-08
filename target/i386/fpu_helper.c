/*
 *  x86 FPU, MMX/3DNow!/SSE/SSE2/SSE3/SSSE3/SSE4/PNI helpers
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include <math.h>
#include "cpu.h"
#include "exec/helper-proto.h"
#include "qemu/host-utils.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "fpu/softfloat.h"
#include "fpu/softfloat-macros.h"

#ifdef CONFIG_SOFTMMU
#include "hw/irq.h"
#endif

#define FPU_RC_MASK         0xc00
#define FPU_RC_NEAR         0x000
#define FPU_RC_DOWN         0x400
#define FPU_RC_UP           0x800
#define FPU_RC_CHOP         0xc00

#define MAXTAN 9223372036854775808.0

/* the following deal with x86 long double-precision numbers */
#define MAXEXPD 0x7fff
#define EXPBIAS 16383
#define EXPD(fp)        (fp.l.upper & 0x7fff)
#define SIGND(fp)       ((fp.l.upper) & 0x8000)
#define MANTD(fp)       (fp.l.lower)
#define BIASEXPONENT(fp) fp.l.upper = (fp.l.upper & ~(0x7fff)) | EXPBIAS

#define FPUS_IE (1 << 0)
#define FPUS_DE (1 << 1)
#define FPUS_ZE (1 << 2)
#define FPUS_OE (1 << 3)
#define FPUS_UE (1 << 4)
#define FPUS_PE (1 << 5)
#define FPUS_SF (1 << 6)
#define FPUS_SE (1 << 7)
#define FPUS_B  (1 << 15)

#define FPUC_EM 0x3f

#define floatx80_lg2 make_floatx80(0x3ffd, 0x9a209a84fbcff799LL)
#define floatx80_lg2_d make_floatx80(0x3ffd, 0x9a209a84fbcff798LL)
#define floatx80_l2e make_floatx80(0x3fff, 0xb8aa3b295c17f0bcLL)
#define floatx80_l2e_d make_floatx80(0x3fff, 0xb8aa3b295c17f0bbLL)
#define floatx80_l2t make_floatx80(0x4000, 0xd49a784bcd1b8afeLL)
#define floatx80_l2t_u make_floatx80(0x4000, 0xd49a784bcd1b8affLL)
#define floatx80_ln2_d make_floatx80(0x3ffe, 0xb17217f7d1cf79abLL)
#define floatx80_pi_d make_floatx80(0x4000, 0xc90fdaa22168c234LL)

#if !defined(CONFIG_USER_ONLY)
static qemu_irq ferr_irq;

void x86_register_ferr_irq(qemu_irq irq)
{
    ferr_irq = irq;
}

static void cpu_clear_ignne(void)
{
    CPUX86State *env = &X86_CPU(first_cpu)->env;
    env->hflags2 &= ~HF2_IGNNE_MASK;
}

void cpu_set_ignne(void)
{
    CPUX86State *env = &X86_CPU(first_cpu)->env;
    env->hflags2 |= HF2_IGNNE_MASK;
    /*
     * We get here in response to a write to port F0h.  The chipset should
     * deassert FP_IRQ and FERR# instead should stay signaled until FPSW_SE is
     * cleared, because FERR# and FP_IRQ are two separate pins on real
     * hardware.  However, we don't model FERR# as a qemu_irq, so we just
     * do directly what the chipset would do, i.e. deassert FP_IRQ.
     */
    qemu_irq_lower(ferr_irq);
}
#endif


static inline void fpush(CPUX86State *env)
{
    env->fpstt = (env->fpstt - 1) & 7;
    env->fptags[env->fpstt] = 0; /* validate stack entry */
}

static inline void fpop(CPUX86State *env)
{
    env->fptags[env->fpstt] = 1; /* invalidate stack entry */
    env->fpstt = (env->fpstt + 1) & 7;
}

static inline floatx80 helper_fldt(CPUX86State *env, target_ulong ptr,
                                   uintptr_t retaddr)
{
    CPU_LDoubleU temp;

    temp.l.lower = cpu_ldq_data_ra(env, ptr, retaddr);
    temp.l.upper = cpu_lduw_data_ra(env, ptr + 8, retaddr);
    return temp.d;
}

static inline void helper_fstt(CPUX86State *env, floatx80 f, target_ulong ptr,
                               uintptr_t retaddr)
{
    CPU_LDoubleU temp;

    temp.d = f;
    cpu_stq_data_ra(env, ptr, temp.l.lower, retaddr);
    cpu_stw_data_ra(env, ptr + 8, temp.l.upper, retaddr);
}

/* x87 FPU helpers */

static inline double floatx80_to_double(CPUX86State *env, floatx80 a)
{
    union {
        float64 f64;
        double d;
    } u;

    u.f64 = floatx80_to_float64(a, &env->fp_status);
    return u.d;
}

static inline floatx80 double_to_floatx80(CPUX86State *env, double a)
{
    union {
        float64 f64;
        double d;
    } u;

    u.d = a;
    return float64_to_floatx80(u.f64, &env->fp_status);
}

static void fpu_set_exception(CPUX86State *env, int mask)
{
    env->fpus |= mask;
    if (env->fpus & (~env->fpuc & FPUC_EM)) {
        env->fpus |= FPUS_SE | FPUS_B;
    }
}

static inline uint8_t save_exception_flags(CPUX86State *env)
{
    uint8_t old_flags = get_float_exception_flags(&env->fp_status);
    set_float_exception_flags(0, &env->fp_status);
    return old_flags;
}

static void merge_exception_flags(CPUX86State *env, uint8_t old_flags)
{
    uint8_t new_flags = get_float_exception_flags(&env->fp_status);
    float_raise(old_flags, &env->fp_status);
    fpu_set_exception(env,
                      ((new_flags & float_flag_invalid ? FPUS_IE : 0) |
                       (new_flags & float_flag_divbyzero ? FPUS_ZE : 0) |
                       (new_flags & float_flag_overflow ? FPUS_OE : 0) |
                       (new_flags & float_flag_underflow ? FPUS_UE : 0) |
                       (new_flags & float_flag_inexact ? FPUS_PE : 0) |
                       (new_flags & float_flag_input_denormal ? FPUS_DE : 0)));
}

static inline floatx80 helper_fdiv(CPUX86State *env, floatx80 a, floatx80 b)
{
    uint8_t old_flags = save_exception_flags(env);
    floatx80 ret = floatx80_div(a, b, &env->fp_status);
    merge_exception_flags(env, old_flags);
    return ret;
}

static void fpu_raise_exception(CPUX86State *env, uintptr_t retaddr)
{
    if (env->cr[0] & CR0_NE_MASK) {
        raise_exception_ra(env, EXCP10_COPR, retaddr);
    }
#if !defined(CONFIG_USER_ONLY)
    else if (ferr_irq && !(env->hflags2 & HF2_IGNNE_MASK)) {
        qemu_irq_raise(ferr_irq);
    }
#endif
}

void helper_flds_FT0(CPUX86State *env, uint32_t val)
{
    uint8_t old_flags = save_exception_flags(env);
    union {
        float32 f;
        uint32_t i;
    } u;

    u.i = val;
    FT0 = float32_to_floatx80(u.f, &env->fp_status);
    merge_exception_flags(env, old_flags);
}

void helper_fldl_FT0(CPUX86State *env, uint64_t val)
{
    uint8_t old_flags = save_exception_flags(env);
    union {
        float64 f;
        uint64_t i;
    } u;

    u.i = val;
    FT0 = float64_to_floatx80(u.f, &env->fp_status);
    merge_exception_flags(env, old_flags);
}

void helper_fildl_FT0(CPUX86State *env, int32_t val)
{
    FT0 = int32_to_floatx80(val, &env->fp_status);
}

void helper_flds_ST0(CPUX86State *env, uint32_t val)
{
    uint8_t old_flags = save_exception_flags(env);
    int new_fpstt;
    union {
        float32 f;
        uint32_t i;
    } u;

    new_fpstt = (env->fpstt - 1) & 7;
    u.i = val;
    env->fpregs[new_fpstt].d = float32_to_floatx80(u.f, &env->fp_status);
    env->fpstt = new_fpstt;
    env->fptags[new_fpstt] = 0; /* validate stack entry */
    merge_exception_flags(env, old_flags);
}

void helper_fldl_ST0(CPUX86State *env, uint64_t val)
{
    uint8_t old_flags = save_exception_flags(env);
    int new_fpstt;
    union {
        float64 f;
        uint64_t i;
    } u;

    new_fpstt = (env->fpstt - 1) & 7;
    u.i = val;
    env->fpregs[new_fpstt].d = float64_to_floatx80(u.f, &env->fp_status);
    env->fpstt = new_fpstt;
    env->fptags[new_fpstt] = 0; /* validate stack entry */
    merge_exception_flags(env, old_flags);
}

void helper_fildl_ST0(CPUX86State *env, int32_t val)
{
    int new_fpstt;

    new_fpstt = (env->fpstt - 1) & 7;
    env->fpregs[new_fpstt].d = int32_to_floatx80(val, &env->fp_status);
    env->fpstt = new_fpstt;
    env->fptags[new_fpstt] = 0; /* validate stack entry */
}

void helper_fildll_ST0(CPUX86State *env, int64_t val)
{
    int new_fpstt;

    new_fpstt = (env->fpstt - 1) & 7;
    env->fpregs[new_fpstt].d = int64_to_floatx80(val, &env->fp_status);
    env->fpstt = new_fpstt;
    env->fptags[new_fpstt] = 0; /* validate stack entry */
}

uint32_t helper_fsts_ST0(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    union {
        float32 f;
        uint32_t i;
    } u;

    u.f = floatx80_to_float32(ST0, &env->fp_status);
    merge_exception_flags(env, old_flags);
    return u.i;
}

uint64_t helper_fstl_ST0(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    union {
        float64 f;
        uint64_t i;
    } u;

    u.f = floatx80_to_float64(ST0, &env->fp_status);
    merge_exception_flags(env, old_flags);
    return u.i;
}

int32_t helper_fist_ST0(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    int32_t val;

    val = floatx80_to_int32(ST0, &env->fp_status);
    if (val != (int16_t)val) {
        set_float_exception_flags(float_flag_invalid, &env->fp_status);
        val = -32768;
    }
    merge_exception_flags(env, old_flags);
    return val;
}

int32_t helper_fistl_ST0(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    int32_t val;

    val = floatx80_to_int32(ST0, &env->fp_status);
    if (get_float_exception_flags(&env->fp_status) & float_flag_invalid) {
        val = 0x80000000;
    }
    merge_exception_flags(env, old_flags);
    return val;
}

int64_t helper_fistll_ST0(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    int64_t val;

    val = floatx80_to_int64(ST0, &env->fp_status);
    if (get_float_exception_flags(&env->fp_status) & float_flag_invalid) {
        val = 0x8000000000000000ULL;
    }
    merge_exception_flags(env, old_flags);
    return val;
}

int32_t helper_fistt_ST0(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    int32_t val;

    val = floatx80_to_int32_round_to_zero(ST0, &env->fp_status);
    if (val != (int16_t)val) {
        set_float_exception_flags(float_flag_invalid, &env->fp_status);
        val = -32768;
    }
    merge_exception_flags(env, old_flags);
    return val;
}

int32_t helper_fisttl_ST0(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    int32_t val;

    val = floatx80_to_int32_round_to_zero(ST0, &env->fp_status);
    if (get_float_exception_flags(&env->fp_status) & float_flag_invalid) {
        val = 0x80000000;
    }
    merge_exception_flags(env, old_flags);
    return val;
}

int64_t helper_fisttll_ST0(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    int64_t val;

    val = floatx80_to_int64_round_to_zero(ST0, &env->fp_status);
    if (get_float_exception_flags(&env->fp_status) & float_flag_invalid) {
        val = 0x8000000000000000ULL;
    }
    merge_exception_flags(env, old_flags);
    return val;
}

void helper_fldt_ST0(CPUX86State *env, target_ulong ptr)
{
    int new_fpstt;

    new_fpstt = (env->fpstt - 1) & 7;
    env->fpregs[new_fpstt].d = helper_fldt(env, ptr, GETPC());
    env->fpstt = new_fpstt;
    env->fptags[new_fpstt] = 0; /* validate stack entry */
}

void helper_fstt_ST0(CPUX86State *env, target_ulong ptr)
{
    helper_fstt(env, ST0, ptr, GETPC());
}

void helper_fpush(CPUX86State *env)
{
    fpush(env);
}

void helper_fpop(CPUX86State *env)
{
    fpop(env);
}

void helper_fdecstp(CPUX86State *env)
{
    env->fpstt = (env->fpstt - 1) & 7;
    env->fpus &= ~0x4700;
}

void helper_fincstp(CPUX86State *env)
{
    env->fpstt = (env->fpstt + 1) & 7;
    env->fpus &= ~0x4700;
}

/* FPU move */

void helper_ffree_STN(CPUX86State *env, int st_index)
{
    env->fptags[(env->fpstt + st_index) & 7] = 1;
}

void helper_fmov_ST0_FT0(CPUX86State *env)
{
    ST0 = FT0;
}

void helper_fmov_FT0_STN(CPUX86State *env, int st_index)
{
    FT0 = ST(st_index);
}

void helper_fmov_ST0_STN(CPUX86State *env, int st_index)
{
    ST0 = ST(st_index);
}

void helper_fmov_STN_ST0(CPUX86State *env, int st_index)
{
    ST(st_index) = ST0;
}

void helper_fxchg_ST0_STN(CPUX86State *env, int st_index)
{
    floatx80 tmp;

    tmp = ST(st_index);
    ST(st_index) = ST0;
    ST0 = tmp;
}

/* FPU operations */

static const int fcom_ccval[4] = {0x0100, 0x4000, 0x0000, 0x4500};

void helper_fcom_ST0_FT0(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    FloatRelation ret;

    ret = floatx80_compare(ST0, FT0, &env->fp_status);
    env->fpus = (env->fpus & ~0x4500) | fcom_ccval[ret + 1];
    merge_exception_flags(env, old_flags);
}

void helper_fucom_ST0_FT0(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    FloatRelation ret;

    ret = floatx80_compare_quiet(ST0, FT0, &env->fp_status);
    env->fpus = (env->fpus & ~0x4500) | fcom_ccval[ret + 1];
    merge_exception_flags(env, old_flags);
}

static const int fcomi_ccval[4] = {CC_C, CC_Z, 0, CC_Z | CC_P | CC_C};

void helper_fcomi_ST0_FT0(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    int eflags;
    FloatRelation ret;

    ret = floatx80_compare(ST0, FT0, &env->fp_status);
    eflags = cpu_cc_compute_all(env, CC_OP);
    eflags = (eflags & ~(CC_Z | CC_P | CC_C)) | fcomi_ccval[ret + 1];
    CC_SRC = eflags;
    merge_exception_flags(env, old_flags);
}

void helper_fucomi_ST0_FT0(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    int eflags;
    FloatRelation ret;

    ret = floatx80_compare_quiet(ST0, FT0, &env->fp_status);
    eflags = cpu_cc_compute_all(env, CC_OP);
    eflags = (eflags & ~(CC_Z | CC_P | CC_C)) | fcomi_ccval[ret + 1];
    CC_SRC = eflags;
    merge_exception_flags(env, old_flags);
}

void helper_fadd_ST0_FT0(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    ST0 = floatx80_add(ST0, FT0, &env->fp_status);
    merge_exception_flags(env, old_flags);
}

void helper_fmul_ST0_FT0(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    ST0 = floatx80_mul(ST0, FT0, &env->fp_status);
    merge_exception_flags(env, old_flags);
}

void helper_fsub_ST0_FT0(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    ST0 = floatx80_sub(ST0, FT0, &env->fp_status);
    merge_exception_flags(env, old_flags);
}

void helper_fsubr_ST0_FT0(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    ST0 = floatx80_sub(FT0, ST0, &env->fp_status);
    merge_exception_flags(env, old_flags);
}

void helper_fdiv_ST0_FT0(CPUX86State *env)
{
    ST0 = helper_fdiv(env, ST0, FT0);
}

void helper_fdivr_ST0_FT0(CPUX86State *env)
{
    ST0 = helper_fdiv(env, FT0, ST0);
}

/* fp operations between STN and ST0 */

void helper_fadd_STN_ST0(CPUX86State *env, int st_index)
{
    uint8_t old_flags = save_exception_flags(env);
    ST(st_index) = floatx80_add(ST(st_index), ST0, &env->fp_status);
    merge_exception_flags(env, old_flags);
}

void helper_fmul_STN_ST0(CPUX86State *env, int st_index)
{
    uint8_t old_flags = save_exception_flags(env);
    ST(st_index) = floatx80_mul(ST(st_index), ST0, &env->fp_status);
    merge_exception_flags(env, old_flags);
}

void helper_fsub_STN_ST0(CPUX86State *env, int st_index)
{
    uint8_t old_flags = save_exception_flags(env);
    ST(st_index) = floatx80_sub(ST(st_index), ST0, &env->fp_status);
    merge_exception_flags(env, old_flags);
}

void helper_fsubr_STN_ST0(CPUX86State *env, int st_index)
{
    uint8_t old_flags = save_exception_flags(env);
    ST(st_index) = floatx80_sub(ST0, ST(st_index), &env->fp_status);
    merge_exception_flags(env, old_flags);
}

void helper_fdiv_STN_ST0(CPUX86State *env, int st_index)
{
    floatx80 *p;

    p = &ST(st_index);
    *p = helper_fdiv(env, *p, ST0);
}

void helper_fdivr_STN_ST0(CPUX86State *env, int st_index)
{
    floatx80 *p;

    p = &ST(st_index);
    *p = helper_fdiv(env, ST0, *p);
}

/* misc FPU operations */
void helper_fchs_ST0(CPUX86State *env)
{
    ST0 = floatx80_chs(ST0);
}

void helper_fabs_ST0(CPUX86State *env)
{
    ST0 = floatx80_abs(ST0);
}

void helper_fld1_ST0(CPUX86State *env)
{
    ST0 = floatx80_one;
}

void helper_fldl2t_ST0(CPUX86State *env)
{
    switch (env->fpuc & FPU_RC_MASK) {
    case FPU_RC_UP:
        ST0 = floatx80_l2t_u;
        break;
    default:
        ST0 = floatx80_l2t;
        break;
    }
}

void helper_fldl2e_ST0(CPUX86State *env)
{
    switch (env->fpuc & FPU_RC_MASK) {
    case FPU_RC_DOWN:
    case FPU_RC_CHOP:
        ST0 = floatx80_l2e_d;
        break;
    default:
        ST0 = floatx80_l2e;
        break;
    }
}

void helper_fldpi_ST0(CPUX86State *env)
{
    switch (env->fpuc & FPU_RC_MASK) {
    case FPU_RC_DOWN:
    case FPU_RC_CHOP:
        ST0 = floatx80_pi_d;
        break;
    default:
        ST0 = floatx80_pi;
        break;
    }
}

void helper_fldlg2_ST0(CPUX86State *env)
{
    switch (env->fpuc & FPU_RC_MASK) {
    case FPU_RC_DOWN:
    case FPU_RC_CHOP:
        ST0 = floatx80_lg2_d;
        break;
    default:
        ST0 = floatx80_lg2;
        break;
    }
}

void helper_fldln2_ST0(CPUX86State *env)
{
    switch (env->fpuc & FPU_RC_MASK) {
    case FPU_RC_DOWN:
    case FPU_RC_CHOP:
        ST0 = floatx80_ln2_d;
        break;
    default:
        ST0 = floatx80_ln2;
        break;
    }
}

void helper_fldz_ST0(CPUX86State *env)
{
    ST0 = floatx80_zero;
}

void helper_fldz_FT0(CPUX86State *env)
{
    FT0 = floatx80_zero;
}

uint32_t helper_fnstsw(CPUX86State *env)
{
    return (env->fpus & ~0x3800) | (env->fpstt & 0x7) << 11;
}

uint32_t helper_fnstcw(CPUX86State *env)
{
    return env->fpuc;
}

void update_fp_status(CPUX86State *env)
{
    int rnd_type;

    /* set rounding mode */
    switch (env->fpuc & FPU_RC_MASK) {
    default:
    case FPU_RC_NEAR:
        rnd_type = float_round_nearest_even;
        break;
    case FPU_RC_DOWN:
        rnd_type = float_round_down;
        break;
    case FPU_RC_UP:
        rnd_type = float_round_up;
        break;
    case FPU_RC_CHOP:
        rnd_type = float_round_to_zero;
        break;
    }
    set_float_rounding_mode(rnd_type, &env->fp_status);
    switch ((env->fpuc >> 8) & 3) {
    case 0:
        rnd_type = 32;
        break;
    case 2:
        rnd_type = 64;
        break;
    case 3:
    default:
        rnd_type = 80;
        break;
    }
    set_floatx80_rounding_precision(rnd_type, &env->fp_status);
}

void helper_fldcw(CPUX86State *env, uint32_t val)
{
    cpu_set_fpuc(env, val);
}

void helper_fclex(CPUX86State *env)
{
    env->fpus &= 0x7f00;
}

void helper_fwait(CPUX86State *env)
{
    if (env->fpus & FPUS_SE) {
        fpu_raise_exception(env, GETPC());
    }
}

void helper_fninit(CPUX86State *env)
{
    env->fpus = 0;
    env->fpstt = 0;
    cpu_set_fpuc(env, 0x37f);
    env->fptags[0] = 1;
    env->fptags[1] = 1;
    env->fptags[2] = 1;
    env->fptags[3] = 1;
    env->fptags[4] = 1;
    env->fptags[5] = 1;
    env->fptags[6] = 1;
    env->fptags[7] = 1;
}

/* BCD ops */

void helper_fbld_ST0(CPUX86State *env, target_ulong ptr)
{
    floatx80 tmp;
    uint64_t val;
    unsigned int v;
    int i;

    val = 0;
    for (i = 8; i >= 0; i--) {
        v = cpu_ldub_data_ra(env, ptr + i, GETPC());
        val = (val * 100) + ((v >> 4) * 10) + (v & 0xf);
    }
    tmp = int64_to_floatx80(val, &env->fp_status);
    if (cpu_ldub_data_ra(env, ptr + 9, GETPC()) & 0x80) {
        tmp = floatx80_chs(tmp);
    }
    fpush(env);
    ST0 = tmp;
}

void helper_fbst_ST0(CPUX86State *env, target_ulong ptr)
{
    uint8_t old_flags = save_exception_flags(env);
    int v;
    target_ulong mem_ref, mem_end;
    int64_t val;
    CPU_LDoubleU temp;

    temp.d = ST0;

    val = floatx80_to_int64(ST0, &env->fp_status);
    mem_ref = ptr;
    if (val >= 1000000000000000000LL || val <= -1000000000000000000LL) {
        set_float_exception_flags(float_flag_invalid, &env->fp_status);
        while (mem_ref < ptr + 7) {
            cpu_stb_data_ra(env, mem_ref++, 0, GETPC());
        }
        cpu_stb_data_ra(env, mem_ref++, 0xc0, GETPC());
        cpu_stb_data_ra(env, mem_ref++, 0xff, GETPC());
        cpu_stb_data_ra(env, mem_ref++, 0xff, GETPC());
        merge_exception_flags(env, old_flags);
        return;
    }
    mem_end = mem_ref + 9;
    if (SIGND(temp)) {
        cpu_stb_data_ra(env, mem_end, 0x80, GETPC());
        val = -val;
    } else {
        cpu_stb_data_ra(env, mem_end, 0x00, GETPC());
    }
    while (mem_ref < mem_end) {
        if (val == 0) {
            break;
        }
        v = val % 100;
        val = val / 100;
        v = ((v / 10) << 4) | (v % 10);
        cpu_stb_data_ra(env, mem_ref++, v, GETPC());
    }
    while (mem_ref < mem_end) {
        cpu_stb_data_ra(env, mem_ref++, 0, GETPC());
    }
    merge_exception_flags(env, old_flags);
}

/* 128-bit significand of log(2).  */
#define ln2_sig_high 0xb17217f7d1cf79abULL
#define ln2_sig_low 0xc9e3b39803f2f6afULL

/*
 * Polynomial coefficients for an approximation to (2^x - 1) / x, on
 * the interval [-1/64, 1/64].
 */
#define f2xm1_coeff_0 make_floatx80(0x3ffe, 0xb17217f7d1cf79acULL)
#define f2xm1_coeff_0_low make_floatx80(0xbfbc, 0xd87edabf495b3762ULL)
#define f2xm1_coeff_1 make_floatx80(0x3ffc, 0xf5fdeffc162c7543ULL)
#define f2xm1_coeff_2 make_floatx80(0x3ffa, 0xe35846b82505fcc7ULL)
#define f2xm1_coeff_3 make_floatx80(0x3ff8, 0x9d955b7dd273b899ULL)
#define f2xm1_coeff_4 make_floatx80(0x3ff5, 0xaec3ff3c4ef4ac0cULL)
#define f2xm1_coeff_5 make_floatx80(0x3ff2, 0xa184897c3a7f0de9ULL)
#define f2xm1_coeff_6 make_floatx80(0x3fee, 0xffe634d0ec30d504ULL)
#define f2xm1_coeff_7 make_floatx80(0x3feb, 0xb160111d2db515e4ULL)

struct f2xm1_data {
    /*
     * A value very close to a multiple of 1/32, such that 2^t and 2^t - 1
     * are very close to exact floatx80 values.
     */
    floatx80 t;
    /* The value of 2^t.  */
    floatx80 exp2;
    /* The value of 2^t - 1.  */
    floatx80 exp2m1;
};

static const struct f2xm1_data f2xm1_table[65] = {
    { make_floatx80(0xbfff, 0x8000000000000000ULL),
      make_floatx80(0x3ffe, 0x8000000000000000ULL),
      make_floatx80(0xbffe, 0x8000000000000000ULL) },
    { make_floatx80(0xbffe, 0xf800000000002e7eULL),
      make_floatx80(0x3ffe, 0x82cd8698ac2b9160ULL),
      make_floatx80(0xbffd, 0xfa64f2cea7a8dd40ULL) },
    { make_floatx80(0xbffe, 0xefffffffffffe960ULL),
      make_floatx80(0x3ffe, 0x85aac367cc488345ULL),
      make_floatx80(0xbffd, 0xf4aa7930676ef976ULL) },
    { make_floatx80(0xbffe, 0xe800000000006f10ULL),
      make_floatx80(0x3ffe, 0x88980e8092da5c14ULL),
      make_floatx80(0xbffd, 0xeecfe2feda4b47d8ULL) },
    { make_floatx80(0xbffe, 0xe000000000008a45ULL),
      make_floatx80(0x3ffe, 0x8b95c1e3ea8ba2a5ULL),
      make_floatx80(0xbffd, 0xe8d47c382ae8bab6ULL) },
    { make_floatx80(0xbffe, 0xd7ffffffffff8a9eULL),
      make_floatx80(0x3ffe, 0x8ea4398b45cd8116ULL),
      make_floatx80(0xbffd, 0xe2b78ce97464fdd4ULL) },
    { make_floatx80(0xbffe, 0xd0000000000019a0ULL),
      make_floatx80(0x3ffe, 0x91c3d373ab11b919ULL),
      make_floatx80(0xbffd, 0xdc785918a9dc8dceULL) },
    { make_floatx80(0xbffe, 0xc7ffffffffff14dfULL),
      make_floatx80(0x3ffe, 0x94f4efa8fef76836ULL),
      make_floatx80(0xbffd, 0xd61620ae02112f94ULL) },
    { make_floatx80(0xbffe, 0xc000000000006530ULL),
      make_floatx80(0x3ffe, 0x9837f0518db87fbbULL),
      make_floatx80(0xbffd, 0xcf901f5ce48f008aULL) },
    { make_floatx80(0xbffe, 0xb7ffffffffff1723ULL),
      make_floatx80(0x3ffe, 0x9b8d39b9d54eb74cULL),
      make_floatx80(0xbffd, 0xc8e58c8c55629168ULL) },
    { make_floatx80(0xbffe, 0xb00000000000b5e1ULL),
      make_floatx80(0x3ffe, 0x9ef5326091a0c366ULL),
      make_floatx80(0xbffd, 0xc2159b3edcbe7934ULL) },
    { make_floatx80(0xbffe, 0xa800000000006f8aULL),
      make_floatx80(0x3ffe, 0xa27043030c49370aULL),
      make_floatx80(0xbffd, 0xbb1f79f9e76d91ecULL) },
    { make_floatx80(0xbffe, 0x9fffffffffff816aULL),
      make_floatx80(0x3ffe, 0xa5fed6a9b15171cfULL),
      make_floatx80(0xbffd, 0xb40252ac9d5d1c62ULL) },
    { make_floatx80(0xbffe, 0x97ffffffffffb621ULL),
      make_floatx80(0x3ffe, 0xa9a15ab4ea7c30e6ULL),
      make_floatx80(0xbffd, 0xacbd4a962b079e34ULL) },
    { make_floatx80(0xbffe, 0x8fffffffffff162bULL),
      make_floatx80(0x3ffe, 0xad583eea42a1b886ULL),
      make_floatx80(0xbffd, 0xa54f822b7abc8ef4ULL) },
    { make_floatx80(0xbffe, 0x87ffffffffff4d34ULL),
      make_floatx80(0x3ffe, 0xb123f581d2ac7b51ULL),
      make_floatx80(0xbffd, 0x9db814fc5aa7095eULL) },
    { make_floatx80(0xbffe, 0x800000000000227dULL),
      make_floatx80(0x3ffe, 0xb504f333f9de539dULL),
      make_floatx80(0xbffd, 0x95f619980c4358c6ULL) },
    { make_floatx80(0xbffd, 0xefffffffffff3978ULL),
      make_floatx80(0x3ffe, 0xb8fbaf4762fbd0a1ULL),
      make_floatx80(0xbffd, 0x8e08a1713a085ebeULL) },
    { make_floatx80(0xbffd, 0xe00000000000df81ULL),
      make_floatx80(0x3ffe, 0xbd08a39f580bfd8cULL),
      make_floatx80(0xbffd, 0x85eeb8c14fe804e8ULL) },
    { make_floatx80(0xbffd, 0xd00000000000bccfULL),
      make_floatx80(0x3ffe, 0xc12c4cca667062f6ULL),
      make_floatx80(0xbffc, 0xfb4eccd6663e7428ULL) },
    { make_floatx80(0xbffd, 0xc00000000000eff0ULL),
      make_floatx80(0x3ffe, 0xc5672a1155069abeULL),
      make_floatx80(0xbffc, 0xea6357baabe59508ULL) },
    { make_floatx80(0xbffd, 0xb000000000000fe6ULL),
      make_floatx80(0x3ffe, 0xc9b9bd866e2f234bULL),
      make_floatx80(0xbffc, 0xd91909e6474372d4ULL) },
    { make_floatx80(0xbffd, 0x9fffffffffff2172ULL),
      make_floatx80(0x3ffe, 0xce248c151f84bf00ULL),
      make_floatx80(0xbffc, 0xc76dcfab81ed0400ULL) },
    { make_floatx80(0xbffd, 0x8fffffffffffafffULL),
      make_floatx80(0x3ffe, 0xd2a81d91f12afb2bULL),
      make_floatx80(0xbffc, 0xb55f89b83b541354ULL) },
    { make_floatx80(0xbffc, 0xffffffffffff81a3ULL),
      make_floatx80(0x3ffe, 0xd744fccad69d7d5eULL),
      make_floatx80(0xbffc, 0xa2ec0cd4a58a0a88ULL) },
    { make_floatx80(0xbffc, 0xdfffffffffff1568ULL),
      make_floatx80(0x3ffe, 0xdbfbb797daf25a44ULL),
      make_floatx80(0xbffc, 0x901121a0943696f0ULL) },
    { make_floatx80(0xbffc, 0xbfffffffffff68daULL),
      make_floatx80(0x3ffe, 0xe0ccdeec2a94f811ULL),
      make_floatx80(0xbffb, 0xf999089eab583f78ULL) },
    { make_floatx80(0xbffc, 0x9fffffffffff4690ULL),
      make_floatx80(0x3ffe, 0xe5b906e77c83657eULL),
      make_floatx80(0xbffb, 0xd237c8c41be4d410ULL) },
    { make_floatx80(0xbffb, 0xffffffffffff8aeeULL),
      make_floatx80(0x3ffe, 0xeac0c6e7dd24427cULL),
      make_floatx80(0xbffb, 0xa9f9c8c116ddec20ULL) },
    { make_floatx80(0xbffb, 0xbfffffffffff2d18ULL),
      make_floatx80(0x3ffe, 0xefe4b99bdcdb06ebULL),
      make_floatx80(0xbffb, 0x80da33211927c8a8ULL) },
    { make_floatx80(0xbffa, 0xffffffffffff8ccbULL),
      make_floatx80(0x3ffe, 0xf5257d152486d0f4ULL),
      make_floatx80(0xbffa, 0xada82eadb792f0c0ULL) },
    { make_floatx80(0xbff9, 0xffffffffffff11feULL),
      make_floatx80(0x3ffe, 0xfa83b2db722a0846ULL),
      make_floatx80(0xbff9, 0xaf89a491babef740ULL) },
    { floatx80_zero,
      make_floatx80(0x3fff, 0x8000000000000000ULL),
      floatx80_zero },
    { make_floatx80(0x3ff9, 0xffffffffffff2680ULL),
      make_floatx80(0x3fff, 0x82cd8698ac2b9f6fULL),
      make_floatx80(0x3ff9, 0xb361a62b0ae7dbc0ULL) },
    { make_floatx80(0x3ffb, 0x800000000000b500ULL),
      make_floatx80(0x3fff, 0x85aac367cc488345ULL),
      make_floatx80(0x3ffa, 0xb5586cf9891068a0ULL) },
    { make_floatx80(0x3ffb, 0xbfffffffffff4b67ULL),
      make_floatx80(0x3fff, 0x88980e8092da7cceULL),
      make_floatx80(0x3ffb, 0x8980e8092da7cce0ULL) },
    { make_floatx80(0x3ffb, 0xffffffffffffff57ULL),
      make_floatx80(0x3fff, 0x8b95c1e3ea8bd6dfULL),
      make_floatx80(0x3ffb, 0xb95c1e3ea8bd6df0ULL) },
    { make_floatx80(0x3ffc, 0x9fffffffffff811fULL),
      make_floatx80(0x3fff, 0x8ea4398b45cd4780ULL),
      make_floatx80(0x3ffb, 0xea4398b45cd47800ULL) },
    { make_floatx80(0x3ffc, 0xbfffffffffff9980ULL),
      make_floatx80(0x3fff, 0x91c3d373ab11b919ULL),
      make_floatx80(0x3ffc, 0x8e1e9b9d588dc8c8ULL) },
    { make_floatx80(0x3ffc, 0xdffffffffffff631ULL),
      make_floatx80(0x3fff, 0x94f4efa8fef70864ULL),
      make_floatx80(0x3ffc, 0xa7a77d47f7b84320ULL) },
    { make_floatx80(0x3ffc, 0xffffffffffff2499ULL),
      make_floatx80(0x3fff, 0x9837f0518db892d4ULL),
      make_floatx80(0x3ffc, 0xc1bf828c6dc496a0ULL) },
    { make_floatx80(0x3ffd, 0x8fffffffffff80fbULL),
      make_floatx80(0x3fff, 0x9b8d39b9d54e3a79ULL),
      make_floatx80(0x3ffc, 0xdc69cdceaa71d3c8ULL) },
    { make_floatx80(0x3ffd, 0x9fffffffffffbc23ULL),
      make_floatx80(0x3fff, 0x9ef5326091a10313ULL),
      make_floatx80(0x3ffc, 0xf7a993048d081898ULL) },
    { make_floatx80(0x3ffd, 0xafffffffffff20ecULL),
      make_floatx80(0x3fff, 0xa27043030c49370aULL),
      make_floatx80(0x3ffd, 0x89c10c0c3124dc28ULL) },
    { make_floatx80(0x3ffd, 0xc00000000000fd2cULL),
      make_floatx80(0x3fff, 0xa5fed6a9b15171cfULL),
      make_floatx80(0x3ffd, 0x97fb5aa6c545c73cULL) },
    { make_floatx80(0x3ffd, 0xd0000000000093beULL),
      make_floatx80(0x3fff, 0xa9a15ab4ea7c30e6ULL),
      make_floatx80(0x3ffd, 0xa6856ad3a9f0c398ULL) },
    { make_floatx80(0x3ffd, 0xe00000000000c2aeULL),
      make_floatx80(0x3fff, 0xad583eea42a17876ULL),
      make_floatx80(0x3ffd, 0xb560fba90a85e1d8ULL) },
    { make_floatx80(0x3ffd, 0xefffffffffff1e3fULL),
      make_floatx80(0x3fff, 0xb123f581d2abef6cULL),
      make_floatx80(0x3ffd, 0xc48fd6074aafbdb0ULL) },
    { make_floatx80(0x3ffd, 0xffffffffffff1c23ULL),
      make_floatx80(0x3fff, 0xb504f333f9de2cadULL),
      make_floatx80(0x3ffd, 0xd413cccfe778b2b4ULL) },
    { make_floatx80(0x3ffe, 0x8800000000006344ULL),
      make_floatx80(0x3fff, 0xb8fbaf4762fbd0a1ULL),
      make_floatx80(0x3ffd, 0xe3eebd1d8bef4284ULL) },
    { make_floatx80(0x3ffe, 0x9000000000005d67ULL),
      make_floatx80(0x3fff, 0xbd08a39f580c668dULL),
      make_floatx80(0x3ffd, 0xf4228e7d60319a34ULL) },
    { make_floatx80(0x3ffe, 0x9800000000009127ULL),
      make_floatx80(0x3fff, 0xc12c4cca6670e042ULL),
      make_floatx80(0x3ffe, 0x82589994cce1c084ULL) },
    { make_floatx80(0x3ffe, 0x9fffffffffff06f9ULL),
      make_floatx80(0x3fff, 0xc5672a11550655c3ULL),
      make_floatx80(0x3ffe, 0x8ace5422aa0cab86ULL) },
    { make_floatx80(0x3ffe, 0xa7fffffffffff80dULL),
      make_floatx80(0x3fff, 0xc9b9bd866e2f234bULL),
      make_floatx80(0x3ffe, 0x93737b0cdc5e4696ULL) },
    { make_floatx80(0x3ffe, 0xafffffffffff1470ULL),
      make_floatx80(0x3fff, 0xce248c151f83fd69ULL),
      make_floatx80(0x3ffe, 0x9c49182a3f07fad2ULL) },
    { make_floatx80(0x3ffe, 0xb800000000000e0aULL),
      make_floatx80(0x3fff, 0xd2a81d91f12aec5cULL),
      make_floatx80(0x3ffe, 0xa5503b23e255d8b8ULL) },
    { make_floatx80(0x3ffe, 0xc00000000000b7faULL),
      make_floatx80(0x3fff, 0xd744fccad69dd630ULL),
      make_floatx80(0x3ffe, 0xae89f995ad3bac60ULL) },
    { make_floatx80(0x3ffe, 0xc800000000003aa6ULL),
      make_floatx80(0x3fff, 0xdbfbb797daf25a44ULL),
      make_floatx80(0x3ffe, 0xb7f76f2fb5e4b488ULL) },
    { make_floatx80(0x3ffe, 0xd00000000000a6aeULL),
      make_floatx80(0x3fff, 0xe0ccdeec2a954685ULL),
      make_floatx80(0x3ffe, 0xc199bdd8552a8d0aULL) },
    { make_floatx80(0x3ffe, 0xd800000000004165ULL),
      make_floatx80(0x3fff, 0xe5b906e77c837155ULL),
      make_floatx80(0x3ffe, 0xcb720dcef906e2aaULL) },
    { make_floatx80(0x3ffe, 0xe00000000000582cULL),
      make_floatx80(0x3fff, 0xeac0c6e7dd24713aULL),
      make_floatx80(0x3ffe, 0xd5818dcfba48e274ULL) },
    { make_floatx80(0x3ffe, 0xe800000000001a5dULL),
      make_floatx80(0x3fff, 0xefe4b99bdcdb06ebULL),
      make_floatx80(0x3ffe, 0xdfc97337b9b60dd6ULL) },
    { make_floatx80(0x3ffe, 0xefffffffffffc1efULL),
      make_floatx80(0x3fff, 0xf5257d152486a2faULL),
      make_floatx80(0x3ffe, 0xea4afa2a490d45f4ULL) },
    { make_floatx80(0x3ffe, 0xf800000000001069ULL),
      make_floatx80(0x3fff, 0xfa83b2db722a0e5cULL),
      make_floatx80(0x3ffe, 0xf50765b6e4541cb8ULL) },
    { make_floatx80(0x3fff, 0x8000000000000000ULL),
      make_floatx80(0x4000, 0x8000000000000000ULL),
      make_floatx80(0x3fff, 0x8000000000000000ULL) },
};

void helper_f2xm1(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    uint64_t sig = extractFloatx80Frac(ST0);
    int32_t exp = extractFloatx80Exp(ST0);
    bool sign = extractFloatx80Sign(ST0);

    if (floatx80_invalid_encoding(ST0)) {
        float_raise(float_flag_invalid, &env->fp_status);
        ST0 = floatx80_default_nan(&env->fp_status);
    } else if (floatx80_is_any_nan(ST0)) {
        if (floatx80_is_signaling_nan(ST0, &env->fp_status)) {
            float_raise(float_flag_invalid, &env->fp_status);
            ST0 = floatx80_silence_nan(ST0, &env->fp_status);
        }
    } else if (exp > 0x3fff ||
               (exp == 0x3fff && sig != (0x8000000000000000ULL))) {
        /* Out of range for the instruction, treat as invalid.  */
        float_raise(float_flag_invalid, &env->fp_status);
        ST0 = floatx80_default_nan(&env->fp_status);
    } else if (exp == 0x3fff) {
        /* Argument 1 or -1, exact result 1 or -0.5.  */
        if (sign) {
            ST0 = make_floatx80(0xbffe, 0x8000000000000000ULL);
        }
    } else if (exp < 0x3fb0) {
        if (!floatx80_is_zero(ST0)) {
            /*
             * Multiplying the argument by an extra-precision version
             * of log(2) is sufficiently precise.  Zero arguments are
             * returned unchanged.
             */
            uint64_t sig0, sig1, sig2;
            if (exp == 0) {
                normalizeFloatx80Subnormal(sig, &exp, &sig);
            }
            mul128By64To192(ln2_sig_high, ln2_sig_low, sig, &sig0, &sig1,
                            &sig2);
            /* This result is inexact.  */
            sig1 |= 1;
            ST0 = normalizeRoundAndPackFloatx80(80, sign, exp, sig0, sig1,
                                                &env->fp_status);
        }
    } else {
        floatx80 tmp, y, accum;
        bool asign, bsign;
        int32_t n, aexp, bexp;
        uint64_t asig0, asig1, asig2, bsig0, bsig1;
        FloatRoundMode save_mode = env->fp_status.float_rounding_mode;
        signed char save_prec = env->fp_status.floatx80_rounding_precision;
        env->fp_status.float_rounding_mode = float_round_nearest_even;
        env->fp_status.floatx80_rounding_precision = 80;

        /* Find the nearest multiple of 1/32 to the argument.  */
        tmp = floatx80_scalbn(ST0, 5, &env->fp_status);
        n = 32 + floatx80_to_int32(tmp, &env->fp_status);
        y = floatx80_sub(ST0, f2xm1_table[n].t, &env->fp_status);

        if (floatx80_is_zero(y)) {
            /*
             * Use the value of 2^t - 1 from the table, to avoid
             * needing to special-case zero as a result of
             * multiplication below.
             */
            ST0 = f2xm1_table[n].t;
            set_float_exception_flags(float_flag_inexact, &env->fp_status);
            env->fp_status.float_rounding_mode = save_mode;
        } else {
            /*
             * Compute the lower parts of a polynomial expansion for
             * (2^y - 1) / y.
             */
            accum = floatx80_mul(f2xm1_coeff_7, y, &env->fp_status);
            accum = floatx80_add(f2xm1_coeff_6, accum, &env->fp_status);
            accum = floatx80_mul(accum, y, &env->fp_status);
            accum = floatx80_add(f2xm1_coeff_5, accum, &env->fp_status);
            accum = floatx80_mul(accum, y, &env->fp_status);
            accum = floatx80_add(f2xm1_coeff_4, accum, &env->fp_status);
            accum = floatx80_mul(accum, y, &env->fp_status);
            accum = floatx80_add(f2xm1_coeff_3, accum, &env->fp_status);
            accum = floatx80_mul(accum, y, &env->fp_status);
            accum = floatx80_add(f2xm1_coeff_2, accum, &env->fp_status);
            accum = floatx80_mul(accum, y, &env->fp_status);
            accum = floatx80_add(f2xm1_coeff_1, accum, &env->fp_status);
            accum = floatx80_mul(accum, y, &env->fp_status);
            accum = floatx80_add(f2xm1_coeff_0_low, accum, &env->fp_status);

            /*
             * The full polynomial expansion is f2xm1_coeff_0 + accum
             * (where accum has much lower magnitude, and so, in
             * particular, carry out of the addition is not possible).
             * (This expansion is only accurate to about 70 bits, not
             * 128 bits.)
             */
            aexp = extractFloatx80Exp(f2xm1_coeff_0);
            asign = extractFloatx80Sign(f2xm1_coeff_0);
            shift128RightJamming(extractFloatx80Frac(accum), 0,
                                 aexp - extractFloatx80Exp(accum),
                                 &asig0, &asig1);
            bsig0 = extractFloatx80Frac(f2xm1_coeff_0);
            bsig1 = 0;
            if (asign == extractFloatx80Sign(accum)) {
                add128(bsig0, bsig1, asig0, asig1, &asig0, &asig1);
            } else {
                sub128(bsig0, bsig1, asig0, asig1, &asig0, &asig1);
            }
            /* And thus compute an approximation to 2^y - 1.  */
            mul128By64To192(asig0, asig1, extractFloatx80Frac(y),
                            &asig0, &asig1, &asig2);
            aexp += extractFloatx80Exp(y) - 0x3ffe;
            asign ^= extractFloatx80Sign(y);
            if (n != 32) {
                /*
                 * Multiply this by the precomputed value of 2^t and
                 * add that of 2^t - 1.
                 */
                mul128By64To192(asig0, asig1,
                                extractFloatx80Frac(f2xm1_table[n].exp2),
                                &asig0, &asig1, &asig2);
                aexp += extractFloatx80Exp(f2xm1_table[n].exp2) - 0x3ffe;
                bexp = extractFloatx80Exp(f2xm1_table[n].exp2m1);
                bsig0 = extractFloatx80Frac(f2xm1_table[n].exp2m1);
                bsig1 = 0;
                if (bexp < aexp) {
                    shift128RightJamming(bsig0, bsig1, aexp - bexp,
                                         &bsig0, &bsig1);
                } else if (aexp < bexp) {
                    shift128RightJamming(asig0, asig1, bexp - aexp,
                                         &asig0, &asig1);
                    aexp = bexp;
                }
                /* The sign of 2^t - 1 is always that of the result.  */
                bsign = extractFloatx80Sign(f2xm1_table[n].exp2m1);
                if (asign == bsign) {
                    /* Avoid possible carry out of the addition.  */
                    shift128RightJamming(asig0, asig1, 1,
                                         &asig0, &asig1);
                    shift128RightJamming(bsig0, bsig1, 1,
                                         &bsig0, &bsig1);
                    ++aexp;
                    add128(asig0, asig1, bsig0, bsig1, &asig0, &asig1);
                } else {
                    sub128(bsig0, bsig1, asig0, asig1, &asig0, &asig1);
                    asign = bsign;
                }
            }
            env->fp_status.float_rounding_mode = save_mode;
            /* This result is inexact.  */
            asig1 |= 1;
            ST0 = normalizeRoundAndPackFloatx80(80, asign, aexp, asig0, asig1,
                                                &env->fp_status);
        }

        env->fp_status.floatx80_rounding_precision = save_prec;
    }
    merge_exception_flags(env, old_flags);
}

void helper_fyl2x(CPUX86State *env)
{
    double fptemp = floatx80_to_double(env, ST0);

    if (fptemp > 0.0) {
        fptemp = log(fptemp) / log(2.0); /* log2(ST) */
        fptemp *= floatx80_to_double(env, ST1);
        ST1 = double_to_floatx80(env, fptemp);
        fpop(env);
    } else {
        env->fpus &= ~0x4700;
        env->fpus |= 0x400;
    }
}

void helper_fptan(CPUX86State *env)
{
    double fptemp = floatx80_to_double(env, ST0);

    if ((fptemp > MAXTAN) || (fptemp < -MAXTAN)) {
        env->fpus |= 0x400;
    } else {
        fptemp = tan(fptemp);
        ST0 = double_to_floatx80(env, fptemp);
        fpush(env);
        ST0 = floatx80_one;
        env->fpus &= ~0x400; /* C2 <-- 0 */
        /* the above code is for |arg| < 2**52 only */
    }
}

void helper_fpatan(CPUX86State *env)
{
    double fptemp, fpsrcop;

    fpsrcop = floatx80_to_double(env, ST1);
    fptemp = floatx80_to_double(env, ST0);
    ST1 = double_to_floatx80(env, atan2(fpsrcop, fptemp));
    fpop(env);
}

void helper_fxtract(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    CPU_LDoubleU temp;

    temp.d = ST0;

    if (floatx80_is_zero(ST0)) {
        /* Easy way to generate -inf and raising division by 0 exception */
        ST0 = floatx80_div(floatx80_chs(floatx80_one), floatx80_zero,
                           &env->fp_status);
        fpush(env);
        ST0 = temp.d;
    } else if (floatx80_invalid_encoding(ST0)) {
        float_raise(float_flag_invalid, &env->fp_status);
        ST0 = floatx80_default_nan(&env->fp_status);
        fpush(env);
        ST0 = ST1;
    } else if (floatx80_is_any_nan(ST0)) {
        if (floatx80_is_signaling_nan(ST0, &env->fp_status)) {
            float_raise(float_flag_invalid, &env->fp_status);
            ST0 = floatx80_silence_nan(ST0, &env->fp_status);
        }
        fpush(env);
        ST0 = ST1;
    } else if (floatx80_is_infinity(ST0)) {
        fpush(env);
        ST0 = ST1;
        ST1 = floatx80_infinity;
    } else {
        int expdif;

        if (EXPD(temp) == 0) {
            int shift = clz64(temp.l.lower);
            temp.l.lower <<= shift;
            expdif = 1 - EXPBIAS - shift;
            float_raise(float_flag_input_denormal, &env->fp_status);
        } else {
            expdif = EXPD(temp) - EXPBIAS;
        }
        /* DP exponent bias */
        ST0 = int32_to_floatx80(expdif, &env->fp_status);
        fpush(env);
        BIASEXPONENT(temp);
        ST0 = temp.d;
    }
    merge_exception_flags(env, old_flags);
}

static void helper_fprem_common(CPUX86State *env, bool mod)
{
    uint8_t old_flags = save_exception_flags(env);
    uint64_t quotient;
    CPU_LDoubleU temp0, temp1;
    int exp0, exp1, expdiff;

    temp0.d = ST0;
    temp1.d = ST1;
    exp0 = EXPD(temp0);
    exp1 = EXPD(temp1);

    env->fpus &= ~0x4700; /* (C3,C2,C1,C0) <-- 0000 */
    if (floatx80_is_zero(ST0) || floatx80_is_zero(ST1) ||
        exp0 == 0x7fff || exp1 == 0x7fff ||
        floatx80_invalid_encoding(ST0) || floatx80_invalid_encoding(ST1)) {
        ST0 = floatx80_modrem(ST0, ST1, mod, &quotient, &env->fp_status);
    } else {
        if (exp0 == 0) {
            exp0 = 1 - clz64(temp0.l.lower);
        }
        if (exp1 == 0) {
            exp1 = 1 - clz64(temp1.l.lower);
        }
        expdiff = exp0 - exp1;
        if (expdiff < 64) {
            ST0 = floatx80_modrem(ST0, ST1, mod, &quotient, &env->fp_status);
            env->fpus |= (quotient & 0x4) << (8 - 2);  /* (C0) <-- q2 */
            env->fpus |= (quotient & 0x2) << (14 - 1); /* (C3) <-- q1 */
            env->fpus |= (quotient & 0x1) << (9 - 0);  /* (C1) <-- q0 */
        } else {
            /*
             * Partial remainder.  This choice of how many bits to
             * process at once is specified in AMD instruction set
             * manuals, and empirically is followed by Intel
             * processors as well; it ensures that the final remainder
             * operation in a loop does produce the correct low three
             * bits of the quotient.  AMD manuals specify that the
             * flags other than C2 are cleared, and empirically Intel
             * processors clear them as well.
             */
            int n = 32 + (expdiff % 32);
            temp1.d = floatx80_scalbn(temp1.d, expdiff - n, &env->fp_status);
            ST0 = floatx80_mod(ST0, temp1.d, &env->fp_status);
            env->fpus |= 0x400;  /* C2 <-- 1 */
        }
    }
    merge_exception_flags(env, old_flags);
}

void helper_fprem1(CPUX86State *env)
{
    helper_fprem_common(env, false);
}

void helper_fprem(CPUX86State *env)
{
    helper_fprem_common(env, true);
}

void helper_fyl2xp1(CPUX86State *env)
{
    double fptemp = floatx80_to_double(env, ST0);

    if ((fptemp + 1.0) > 0.0) {
        fptemp = log(fptemp + 1.0) / log(2.0); /* log2(ST + 1.0) */
        fptemp *= floatx80_to_double(env, ST1);
        ST1 = double_to_floatx80(env, fptemp);
        fpop(env);
    } else {
        env->fpus &= ~0x4700;
        env->fpus |= 0x400;
    }
}

void helper_fsqrt(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    if (floatx80_is_neg(ST0)) {
        env->fpus &= ~0x4700;  /* (C3,C2,C1,C0) <-- 0000 */
        env->fpus |= 0x400;
    }
    ST0 = floatx80_sqrt(ST0, &env->fp_status);
    merge_exception_flags(env, old_flags);
}

void helper_fsincos(CPUX86State *env)
{
    double fptemp = floatx80_to_double(env, ST0);

    if ((fptemp > MAXTAN) || (fptemp < -MAXTAN)) {
        env->fpus |= 0x400;
    } else {
        ST0 = double_to_floatx80(env, sin(fptemp));
        fpush(env);
        ST0 = double_to_floatx80(env, cos(fptemp));
        env->fpus &= ~0x400;  /* C2 <-- 0 */
        /* the above code is for |arg| < 2**63 only */
    }
}

void helper_frndint(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    ST0 = floatx80_round_to_int(ST0, &env->fp_status);
    merge_exception_flags(env, old_flags);
}

void helper_fscale(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    if (floatx80_invalid_encoding(ST1) || floatx80_invalid_encoding(ST0)) {
        float_raise(float_flag_invalid, &env->fp_status);
        ST0 = floatx80_default_nan(&env->fp_status);
    } else if (floatx80_is_any_nan(ST1)) {
        if (floatx80_is_signaling_nan(ST0, &env->fp_status)) {
            float_raise(float_flag_invalid, &env->fp_status);
        }
        ST0 = ST1;
        if (floatx80_is_signaling_nan(ST0, &env->fp_status)) {
            float_raise(float_flag_invalid, &env->fp_status);
            ST0 = floatx80_silence_nan(ST0, &env->fp_status);
        }
    } else if (floatx80_is_infinity(ST1) &&
               !floatx80_invalid_encoding(ST0) &&
               !floatx80_is_any_nan(ST0)) {
        if (floatx80_is_neg(ST1)) {
            if (floatx80_is_infinity(ST0)) {
                float_raise(float_flag_invalid, &env->fp_status);
                ST0 = floatx80_default_nan(&env->fp_status);
            } else {
                ST0 = (floatx80_is_neg(ST0) ?
                       floatx80_chs(floatx80_zero) :
                       floatx80_zero);
            }
        } else {
            if (floatx80_is_zero(ST0)) {
                float_raise(float_flag_invalid, &env->fp_status);
                ST0 = floatx80_default_nan(&env->fp_status);
            } else {
                ST0 = (floatx80_is_neg(ST0) ?
                       floatx80_chs(floatx80_infinity) :
                       floatx80_infinity);
            }
        }
    } else {
        int n;
        signed char save = env->fp_status.floatx80_rounding_precision;
        uint8_t save_flags = get_float_exception_flags(&env->fp_status);
        set_float_exception_flags(0, &env->fp_status);
        n = floatx80_to_int32_round_to_zero(ST1, &env->fp_status);
        set_float_exception_flags(save_flags, &env->fp_status);
        env->fp_status.floatx80_rounding_precision = 80;
        ST0 = floatx80_scalbn(ST0, n, &env->fp_status);
        env->fp_status.floatx80_rounding_precision = save;
    }
    merge_exception_flags(env, old_flags);
}

void helper_fsin(CPUX86State *env)
{
    double fptemp = floatx80_to_double(env, ST0);

    if ((fptemp > MAXTAN) || (fptemp < -MAXTAN)) {
        env->fpus |= 0x400;
    } else {
        ST0 = double_to_floatx80(env, sin(fptemp));
        env->fpus &= ~0x400;  /* C2 <-- 0 */
        /* the above code is for |arg| < 2**53 only */
    }
}

void helper_fcos(CPUX86State *env)
{
    double fptemp = floatx80_to_double(env, ST0);

    if ((fptemp > MAXTAN) || (fptemp < -MAXTAN)) {
        env->fpus |= 0x400;
    } else {
        ST0 = double_to_floatx80(env, cos(fptemp));
        env->fpus &= ~0x400;  /* C2 <-- 0 */
        /* the above code is for |arg| < 2**63 only */
    }
}

void helper_fxam_ST0(CPUX86State *env)
{
    CPU_LDoubleU temp;
    int expdif;

    temp.d = ST0;

    env->fpus &= ~0x4700; /* (C3,C2,C1,C0) <-- 0000 */
    if (SIGND(temp)) {
        env->fpus |= 0x200; /* C1 <-- 1 */
    }

    if (env->fptags[env->fpstt]) {
        env->fpus |= 0x4100; /* Empty */
        return;
    }

    expdif = EXPD(temp);
    if (expdif == MAXEXPD) {
        if (MANTD(temp) == 0x8000000000000000ULL) {
            env->fpus |= 0x500; /* Infinity */
        } else if (MANTD(temp) & 0x8000000000000000ULL) {
            env->fpus |= 0x100; /* NaN */
        }
    } else if (expdif == 0) {
        if (MANTD(temp) == 0) {
            env->fpus |=  0x4000; /* Zero */
        } else {
            env->fpus |= 0x4400; /* Denormal */
        }
    } else if (MANTD(temp) & 0x8000000000000000ULL) {
        env->fpus |= 0x400;
    }
}

static void do_fstenv(CPUX86State *env, target_ulong ptr, int data32,
                      uintptr_t retaddr)
{
    int fpus, fptag, exp, i;
    uint64_t mant;
    CPU_LDoubleU tmp;

    fpus = (env->fpus & ~0x3800) | (env->fpstt & 0x7) << 11;
    fptag = 0;
    for (i = 7; i >= 0; i--) {
        fptag <<= 2;
        if (env->fptags[i]) {
            fptag |= 3;
        } else {
            tmp.d = env->fpregs[i].d;
            exp = EXPD(tmp);
            mant = MANTD(tmp);
            if (exp == 0 && mant == 0) {
                /* zero */
                fptag |= 1;
            } else if (exp == 0 || exp == MAXEXPD
                       || (mant & (1LL << 63)) == 0) {
                /* NaNs, infinity, denormal */
                fptag |= 2;
            }
        }
    }
    if (data32) {
        /* 32 bit */
        cpu_stl_data_ra(env, ptr, env->fpuc, retaddr);
        cpu_stl_data_ra(env, ptr + 4, fpus, retaddr);
        cpu_stl_data_ra(env, ptr + 8, fptag, retaddr);
        cpu_stl_data_ra(env, ptr + 12, 0, retaddr); /* fpip */
        cpu_stl_data_ra(env, ptr + 16, 0, retaddr); /* fpcs */
        cpu_stl_data_ra(env, ptr + 20, 0, retaddr); /* fpoo */
        cpu_stl_data_ra(env, ptr + 24, 0, retaddr); /* fpos */
    } else {
        /* 16 bit */
        cpu_stw_data_ra(env, ptr, env->fpuc, retaddr);
        cpu_stw_data_ra(env, ptr + 2, fpus, retaddr);
        cpu_stw_data_ra(env, ptr + 4, fptag, retaddr);
        cpu_stw_data_ra(env, ptr + 6, 0, retaddr);
        cpu_stw_data_ra(env, ptr + 8, 0, retaddr);
        cpu_stw_data_ra(env, ptr + 10, 0, retaddr);
        cpu_stw_data_ra(env, ptr + 12, 0, retaddr);
    }
}

void helper_fstenv(CPUX86State *env, target_ulong ptr, int data32)
{
    do_fstenv(env, ptr, data32, GETPC());
}

static void cpu_set_fpus(CPUX86State *env, uint16_t fpus)
{
    env->fpstt = (fpus >> 11) & 7;
    env->fpus = fpus & ~0x3800 & ~FPUS_B;
    env->fpus |= env->fpus & FPUS_SE ? FPUS_B : 0;
#if !defined(CONFIG_USER_ONLY)
    if (!(env->fpus & FPUS_SE)) {
        /*
         * Here the processor deasserts FERR#; in response, the chipset deasserts
         * IGNNE#.
         */
        cpu_clear_ignne();
    }
#endif
}

static void do_fldenv(CPUX86State *env, target_ulong ptr, int data32,
                      uintptr_t retaddr)
{
    int i, fpus, fptag;

    if (data32) {
        cpu_set_fpuc(env, cpu_lduw_data_ra(env, ptr, retaddr));
        fpus = cpu_lduw_data_ra(env, ptr + 4, retaddr);
        fptag = cpu_lduw_data_ra(env, ptr + 8, retaddr);
    } else {
        cpu_set_fpuc(env, cpu_lduw_data_ra(env, ptr, retaddr));
        fpus = cpu_lduw_data_ra(env, ptr + 2, retaddr);
        fptag = cpu_lduw_data_ra(env, ptr + 4, retaddr);
    }
    cpu_set_fpus(env, fpus);
    for (i = 0; i < 8; i++) {
        env->fptags[i] = ((fptag & 3) == 3);
        fptag >>= 2;
    }
}

void helper_fldenv(CPUX86State *env, target_ulong ptr, int data32)
{
    do_fldenv(env, ptr, data32, GETPC());
}

void helper_fsave(CPUX86State *env, target_ulong ptr, int data32)
{
    floatx80 tmp;
    int i;

    do_fstenv(env, ptr, data32, GETPC());

    ptr += (14 << data32);
    for (i = 0; i < 8; i++) {
        tmp = ST(i);
        helper_fstt(env, tmp, ptr, GETPC());
        ptr += 10;
    }

    /* fninit */
    env->fpus = 0;
    env->fpstt = 0;
    cpu_set_fpuc(env, 0x37f);
    env->fptags[0] = 1;
    env->fptags[1] = 1;
    env->fptags[2] = 1;
    env->fptags[3] = 1;
    env->fptags[4] = 1;
    env->fptags[5] = 1;
    env->fptags[6] = 1;
    env->fptags[7] = 1;
}

void helper_frstor(CPUX86State *env, target_ulong ptr, int data32)
{
    floatx80 tmp;
    int i;

    do_fldenv(env, ptr, data32, GETPC());
    ptr += (14 << data32);

    for (i = 0; i < 8; i++) {
        tmp = helper_fldt(env, ptr, GETPC());
        ST(i) = tmp;
        ptr += 10;
    }
}

#if defined(CONFIG_USER_ONLY)
void cpu_x86_fsave(CPUX86State *env, target_ulong ptr, int data32)
{
    helper_fsave(env, ptr, data32);
}

void cpu_x86_frstor(CPUX86State *env, target_ulong ptr, int data32)
{
    helper_frstor(env, ptr, data32);
}
#endif

#define XO(X)  offsetof(X86XSaveArea, X)

static void do_xsave_fpu(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    int fpus, fptag, i;
    target_ulong addr;

    fpus = (env->fpus & ~0x3800) | (env->fpstt & 0x7) << 11;
    fptag = 0;
    for (i = 0; i < 8; i++) {
        fptag |= (env->fptags[i] << i);
    }

    cpu_stw_data_ra(env, ptr + XO(legacy.fcw), env->fpuc, ra);
    cpu_stw_data_ra(env, ptr + XO(legacy.fsw), fpus, ra);
    cpu_stw_data_ra(env, ptr + XO(legacy.ftw), fptag ^ 0xff, ra);

    /* In 32-bit mode this is eip, sel, dp, sel.
       In 64-bit mode this is rip, rdp.
       But in either case we don't write actual data, just zeros.  */
    cpu_stq_data_ra(env, ptr + XO(legacy.fpip), 0, ra); /* eip+sel; rip */
    cpu_stq_data_ra(env, ptr + XO(legacy.fpdp), 0, ra); /* edp+sel; rdp */

    addr = ptr + XO(legacy.fpregs);
    for (i = 0; i < 8; i++) {
        floatx80 tmp = ST(i);
        helper_fstt(env, tmp, addr, ra);
        addr += 16;
    }
}

static void do_xsave_mxcsr(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    cpu_stl_data_ra(env, ptr + XO(legacy.mxcsr), env->mxcsr, ra);
    cpu_stl_data_ra(env, ptr + XO(legacy.mxcsr_mask), 0x0000ffff, ra);
}

static void do_xsave_sse(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    int i, nb_xmm_regs;
    target_ulong addr;

    if (env->hflags & HF_CS64_MASK) {
        nb_xmm_regs = 16;
    } else {
        nb_xmm_regs = 8;
    }

    addr = ptr + XO(legacy.xmm_regs);
    for (i = 0; i < nb_xmm_regs; i++) {
        cpu_stq_data_ra(env, addr, env->xmm_regs[i].ZMM_Q(0), ra);
        cpu_stq_data_ra(env, addr + 8, env->xmm_regs[i].ZMM_Q(1), ra);
        addr += 16;
    }
}

static void do_xsave_bndregs(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    target_ulong addr = ptr + offsetof(XSaveBNDREG, bnd_regs);
    int i;

    for (i = 0; i < 4; i++, addr += 16) {
        cpu_stq_data_ra(env, addr, env->bnd_regs[i].lb, ra);
        cpu_stq_data_ra(env, addr + 8, env->bnd_regs[i].ub, ra);
    }
}

static void do_xsave_bndcsr(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    cpu_stq_data_ra(env, ptr + offsetof(XSaveBNDCSR, bndcsr.cfgu),
                    env->bndcs_regs.cfgu, ra);
    cpu_stq_data_ra(env, ptr + offsetof(XSaveBNDCSR, bndcsr.sts),
                    env->bndcs_regs.sts, ra);
}

static void do_xsave_pkru(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    cpu_stq_data_ra(env, ptr, env->pkru, ra);
}

void helper_fxsave(CPUX86State *env, target_ulong ptr)
{
    uintptr_t ra = GETPC();

    /* The operand must be 16 byte aligned */
    if (ptr & 0xf) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }

    do_xsave_fpu(env, ptr, ra);

    if (env->cr[4] & CR4_OSFXSR_MASK) {
        do_xsave_mxcsr(env, ptr, ra);
        /* Fast FXSAVE leaves out the XMM registers */
        if (!(env->efer & MSR_EFER_FFXSR)
            || (env->hflags & HF_CPL_MASK)
            || !(env->hflags & HF_LMA_MASK)) {
            do_xsave_sse(env, ptr, ra);
        }
    }
}

static uint64_t get_xinuse(CPUX86State *env)
{
    uint64_t inuse = -1;

    /* For the most part, we don't track XINUSE.  We could calculate it
       here for all components, but it's probably less work to simply
       indicate in use.  That said, the state of BNDREGS is important
       enough to track in HFLAGS, so we might as well use that here.  */
    if ((env->hflags & HF_MPX_IU_MASK) == 0) {
       inuse &= ~XSTATE_BNDREGS_MASK;
    }
    return inuse;
}

static void do_xsave(CPUX86State *env, target_ulong ptr, uint64_t rfbm,
                     uint64_t inuse, uint64_t opt, uintptr_t ra)
{
    uint64_t old_bv, new_bv;

    /* The OS must have enabled XSAVE.  */
    if (!(env->cr[4] & CR4_OSXSAVE_MASK)) {
        raise_exception_ra(env, EXCP06_ILLOP, ra);
    }

    /* The operand must be 64 byte aligned.  */
    if (ptr & 63) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }

    /* Never save anything not enabled by XCR0.  */
    rfbm &= env->xcr0;
    opt &= rfbm;

    if (opt & XSTATE_FP_MASK) {
        do_xsave_fpu(env, ptr, ra);
    }
    if (rfbm & XSTATE_SSE_MASK) {
        /* Note that saving MXCSR is not suppressed by XSAVEOPT.  */
        do_xsave_mxcsr(env, ptr, ra);
    }
    if (opt & XSTATE_SSE_MASK) {
        do_xsave_sse(env, ptr, ra);
    }
    if (opt & XSTATE_BNDREGS_MASK) {
        do_xsave_bndregs(env, ptr + XO(bndreg_state), ra);
    }
    if (opt & XSTATE_BNDCSR_MASK) {
        do_xsave_bndcsr(env, ptr + XO(bndcsr_state), ra);
    }
    if (opt & XSTATE_PKRU_MASK) {
        do_xsave_pkru(env, ptr + XO(pkru_state), ra);
    }

    /* Update the XSTATE_BV field.  */
    old_bv = cpu_ldq_data_ra(env, ptr + XO(header.xstate_bv), ra);
    new_bv = (old_bv & ~rfbm) | (inuse & rfbm);
    cpu_stq_data_ra(env, ptr + XO(header.xstate_bv), new_bv, ra);
}

void helper_xsave(CPUX86State *env, target_ulong ptr, uint64_t rfbm)
{
    do_xsave(env, ptr, rfbm, get_xinuse(env), -1, GETPC());
}

void helper_xsaveopt(CPUX86State *env, target_ulong ptr, uint64_t rfbm)
{
    uint64_t inuse = get_xinuse(env);
    do_xsave(env, ptr, rfbm, inuse, inuse, GETPC());
}

static void do_xrstor_fpu(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    int i, fpuc, fpus, fptag;
    target_ulong addr;

    fpuc = cpu_lduw_data_ra(env, ptr + XO(legacy.fcw), ra);
    fpus = cpu_lduw_data_ra(env, ptr + XO(legacy.fsw), ra);
    fptag = cpu_lduw_data_ra(env, ptr + XO(legacy.ftw), ra);
    cpu_set_fpuc(env, fpuc);
    cpu_set_fpus(env, fpus);
    fptag ^= 0xff;
    for (i = 0; i < 8; i++) {
        env->fptags[i] = ((fptag >> i) & 1);
    }

    addr = ptr + XO(legacy.fpregs);
    for (i = 0; i < 8; i++) {
        floatx80 tmp = helper_fldt(env, addr, ra);
        ST(i) = tmp;
        addr += 16;
    }
}

static void do_xrstor_mxcsr(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    cpu_set_mxcsr(env, cpu_ldl_data_ra(env, ptr + XO(legacy.mxcsr), ra));
}

static void do_xrstor_sse(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    int i, nb_xmm_regs;
    target_ulong addr;

    if (env->hflags & HF_CS64_MASK) {
        nb_xmm_regs = 16;
    } else {
        nb_xmm_regs = 8;
    }

    addr = ptr + XO(legacy.xmm_regs);
    for (i = 0; i < nb_xmm_regs; i++) {
        env->xmm_regs[i].ZMM_Q(0) = cpu_ldq_data_ra(env, addr, ra);
        env->xmm_regs[i].ZMM_Q(1) = cpu_ldq_data_ra(env, addr + 8, ra);
        addr += 16;
    }
}

static void do_xrstor_bndregs(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    target_ulong addr = ptr + offsetof(XSaveBNDREG, bnd_regs);
    int i;

    for (i = 0; i < 4; i++, addr += 16) {
        env->bnd_regs[i].lb = cpu_ldq_data_ra(env, addr, ra);
        env->bnd_regs[i].ub = cpu_ldq_data_ra(env, addr + 8, ra);
    }
}

static void do_xrstor_bndcsr(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    /* FIXME: Extend highest implemented bit of linear address.  */
    env->bndcs_regs.cfgu
        = cpu_ldq_data_ra(env, ptr + offsetof(XSaveBNDCSR, bndcsr.cfgu), ra);
    env->bndcs_regs.sts
        = cpu_ldq_data_ra(env, ptr + offsetof(XSaveBNDCSR, bndcsr.sts), ra);
}

static void do_xrstor_pkru(CPUX86State *env, target_ulong ptr, uintptr_t ra)
{
    env->pkru = cpu_ldq_data_ra(env, ptr, ra);
}

void helper_fxrstor(CPUX86State *env, target_ulong ptr)
{
    uintptr_t ra = GETPC();

    /* The operand must be 16 byte aligned */
    if (ptr & 0xf) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }

    do_xrstor_fpu(env, ptr, ra);

    if (env->cr[4] & CR4_OSFXSR_MASK) {
        do_xrstor_mxcsr(env, ptr, ra);
        /* Fast FXRSTOR leaves out the XMM registers */
        if (!(env->efer & MSR_EFER_FFXSR)
            || (env->hflags & HF_CPL_MASK)
            || !(env->hflags & HF_LMA_MASK)) {
            do_xrstor_sse(env, ptr, ra);
        }
    }
}

#if defined(CONFIG_USER_ONLY)
void cpu_x86_fxsave(CPUX86State *env, target_ulong ptr)
{
    helper_fxsave(env, ptr);
}

void cpu_x86_fxrstor(CPUX86State *env, target_ulong ptr)
{
    helper_fxrstor(env, ptr);
}
#endif

void helper_xrstor(CPUX86State *env, target_ulong ptr, uint64_t rfbm)
{
    uintptr_t ra = GETPC();
    uint64_t xstate_bv, xcomp_bv, reserve0;

    rfbm &= env->xcr0;

    /* The OS must have enabled XSAVE.  */
    if (!(env->cr[4] & CR4_OSXSAVE_MASK)) {
        raise_exception_ra(env, EXCP06_ILLOP, ra);
    }

    /* The operand must be 64 byte aligned.  */
    if (ptr & 63) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }

    xstate_bv = cpu_ldq_data_ra(env, ptr + XO(header.xstate_bv), ra);

    if ((int64_t)xstate_bv < 0) {
        /* FIXME: Compact form.  */
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }

    /* Standard form.  */

    /* The XSTATE_BV field must not set bits not present in XCR0.  */
    if (xstate_bv & ~env->xcr0) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }

    /* The XCOMP_BV field must be zero.  Note that, as of the April 2016
       revision, the description of the XSAVE Header (Vol 1, Sec 13.4.2)
       describes only XCOMP_BV, but the description of the standard form
       of XRSTOR (Vol 1, Sec 13.8.1) checks bytes 23:8 for zero, which
       includes the next 64-bit field.  */
    xcomp_bv = cpu_ldq_data_ra(env, ptr + XO(header.xcomp_bv), ra);
    reserve0 = cpu_ldq_data_ra(env, ptr + XO(header.reserve0), ra);
    if (xcomp_bv || reserve0) {
        raise_exception_ra(env, EXCP0D_GPF, ra);
    }

    if (rfbm & XSTATE_FP_MASK) {
        if (xstate_bv & XSTATE_FP_MASK) {
            do_xrstor_fpu(env, ptr, ra);
        } else {
            helper_fninit(env);
            memset(env->fpregs, 0, sizeof(env->fpregs));
        }
    }
    if (rfbm & XSTATE_SSE_MASK) {
        /* Note that the standard form of XRSTOR loads MXCSR from memory
           whether or not the XSTATE_BV bit is set.  */
        do_xrstor_mxcsr(env, ptr, ra);
        if (xstate_bv & XSTATE_SSE_MASK) {
            do_xrstor_sse(env, ptr, ra);
        } else {
            /* ??? When AVX is implemented, we may have to be more
               selective in the clearing.  */
            memset(env->xmm_regs, 0, sizeof(env->xmm_regs));
        }
    }
    if (rfbm & XSTATE_BNDREGS_MASK) {
        if (xstate_bv & XSTATE_BNDREGS_MASK) {
            do_xrstor_bndregs(env, ptr + XO(bndreg_state), ra);
            env->hflags |= HF_MPX_IU_MASK;
        } else {
            memset(env->bnd_regs, 0, sizeof(env->bnd_regs));
            env->hflags &= ~HF_MPX_IU_MASK;
        }
    }
    if (rfbm & XSTATE_BNDCSR_MASK) {
        if (xstate_bv & XSTATE_BNDCSR_MASK) {
            do_xrstor_bndcsr(env, ptr + XO(bndcsr_state), ra);
        } else {
            memset(&env->bndcs_regs, 0, sizeof(env->bndcs_regs));
        }
        cpu_sync_bndcs_hflags(env);
    }
    if (rfbm & XSTATE_PKRU_MASK) {
        uint64_t old_pkru = env->pkru;
        if (xstate_bv & XSTATE_PKRU_MASK) {
            do_xrstor_pkru(env, ptr + XO(pkru_state), ra);
        } else {
            env->pkru = 0;
        }
        if (env->pkru != old_pkru) {
            CPUState *cs = env_cpu(env);
            tlb_flush(cs);
        }
    }
}

#undef XO

uint64_t helper_xgetbv(CPUX86State *env, uint32_t ecx)
{
    /* The OS must have enabled XSAVE.  */
    if (!(env->cr[4] & CR4_OSXSAVE_MASK)) {
        raise_exception_ra(env, EXCP06_ILLOP, GETPC());
    }

    switch (ecx) {
    case 0:
        return env->xcr0;
    case 1:
        if (env->features[FEAT_XSAVE] & CPUID_XSAVE_XGETBV1) {
            return env->xcr0 & get_xinuse(env);
        }
        break;
    }
    raise_exception_ra(env, EXCP0D_GPF, GETPC());
}

void helper_xsetbv(CPUX86State *env, uint32_t ecx, uint64_t mask)
{
    uint32_t dummy, ena_lo, ena_hi;
    uint64_t ena;

    /* The OS must have enabled XSAVE.  */
    if (!(env->cr[4] & CR4_OSXSAVE_MASK)) {
        raise_exception_ra(env, EXCP06_ILLOP, GETPC());
    }

    /* Only XCR0 is defined at present; the FPU may not be disabled.  */
    if (ecx != 0 || (mask & XSTATE_FP_MASK) == 0) {
        goto do_gpf;
    }

    /* Disallow enabling unimplemented features.  */
    cpu_x86_cpuid(env, 0x0d, 0, &ena_lo, &dummy, &dummy, &ena_hi);
    ena = ((uint64_t)ena_hi << 32) | ena_lo;
    if (mask & ~ena) {
        goto do_gpf;
    }

    /* Disallow enabling only half of MPX.  */
    if ((mask ^ (mask * (XSTATE_BNDCSR_MASK / XSTATE_BNDREGS_MASK)))
        & XSTATE_BNDCSR_MASK) {
        goto do_gpf;
    }

    env->xcr0 = mask;
    cpu_sync_bndcs_hflags(env);
    return;

 do_gpf:
    raise_exception_ra(env, EXCP0D_GPF, GETPC());
}

/* MMX/SSE */
/* XXX: optimize by storing fptt and fptags in the static cpu state */

#define SSE_DAZ             0x0040
#define SSE_RC_MASK         0x6000
#define SSE_RC_NEAR         0x0000
#define SSE_RC_DOWN         0x2000
#define SSE_RC_UP           0x4000
#define SSE_RC_CHOP         0x6000
#define SSE_FZ              0x8000

void update_mxcsr_status(CPUX86State *env)
{
    uint32_t mxcsr = env->mxcsr;
    int rnd_type;

    /* set rounding mode */
    switch (mxcsr & SSE_RC_MASK) {
    default:
    case SSE_RC_NEAR:
        rnd_type = float_round_nearest_even;
        break;
    case SSE_RC_DOWN:
        rnd_type = float_round_down;
        break;
    case SSE_RC_UP:
        rnd_type = float_round_up;
        break;
    case SSE_RC_CHOP:
        rnd_type = float_round_to_zero;
        break;
    }
    set_float_rounding_mode(rnd_type, &env->sse_status);

    /* set denormals are zero */
    set_flush_inputs_to_zero((mxcsr & SSE_DAZ) ? 1 : 0, &env->sse_status);

    /* set flush to zero */
    set_flush_to_zero((mxcsr & SSE_FZ) ? 1 : 0, &env->fp_status);
}

void helper_ldmxcsr(CPUX86State *env, uint32_t val)
{
    cpu_set_mxcsr(env, val);
}

void helper_enter_mmx(CPUX86State *env)
{
    env->fpstt = 0;
    *(uint32_t *)(env->fptags) = 0;
    *(uint32_t *)(env->fptags + 4) = 0;
}

void helper_emms(CPUX86State *env)
{
    /* set to empty state */
    *(uint32_t *)(env->fptags) = 0x01010101;
    *(uint32_t *)(env->fptags + 4) = 0x01010101;
}

/* XXX: suppress */
void helper_movq(CPUX86State *env, void *d, void *s)
{
    *(uint64_t *)d = *(uint64_t *)s;
}

#define SHIFT 0
#include "ops_sse.h"

#define SHIFT 1
#include "ops_sse.h"
