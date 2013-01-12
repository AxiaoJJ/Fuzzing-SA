#include "exec/def-helper.h"

DEF_HELPER_3(raise_exception_err, void, env, i32, i32)
DEF_HELPER_2(raise_exception, void, env, i32)
DEF_HELPER_4(tw, void, env, tl, tl, i32)
#if defined(TARGET_PPC64)
DEF_HELPER_4(td, void, env, tl, tl, i32)
#endif
#if !defined(CONFIG_USER_ONLY)
DEF_HELPER_2(store_msr, void, env, tl)
DEF_HELPER_1(rfi, void, env)
DEF_HELPER_1(rfsvc, void, env)
DEF_HELPER_1(40x_rfci, void, env)
DEF_HELPER_1(rfci, void, env)
DEF_HELPER_1(rfdi, void, env)
DEF_HELPER_1(rfmci, void, env)
#if defined(TARGET_PPC64)
DEF_HELPER_1(rfid, void, env)
DEF_HELPER_1(hrfid, void, env)
#endif
#endif

DEF_HELPER_3(lmw, void, env, tl, i32)
DEF_HELPER_3(stmw, void, env, tl, i32)
DEF_HELPER_4(lsw, void, env, tl, i32, i32)
DEF_HELPER_5(lswx, void, env, tl, i32, i32, i32)
DEF_HELPER_4(stsw, void, env, tl, i32, i32)
DEF_HELPER_2(dcbz, void, env, tl)
DEF_HELPER_2(dcbz_970, void, env, tl)
DEF_HELPER_2(icbi, void, env, tl)
DEF_HELPER_5(lscbx, tl, env, tl, i32, i32, i32)

#if defined(TARGET_PPC64)
DEF_HELPER_FLAGS_2(mulhd, TCG_CALL_NO_RWG_SE, i64, i64, i64)
DEF_HELPER_FLAGS_2(mulhdu, TCG_CALL_NO_RWG_SE, i64, i64, i64)
DEF_HELPER_3(mulldo, i64, env, i64, i64)
#endif

DEF_HELPER_FLAGS_1(cntlzw, TCG_CALL_NO_RWG_SE, tl, tl)
DEF_HELPER_FLAGS_1(popcntb, TCG_CALL_NO_RWG_SE, tl, tl)
DEF_HELPER_FLAGS_1(popcntw, TCG_CALL_NO_RWG_SE, tl, tl)
DEF_HELPER_3(sraw, tl, env, tl, tl)
#if defined(TARGET_PPC64)
DEF_HELPER_FLAGS_1(cntlzd, TCG_CALL_NO_RWG_SE, tl, tl)
DEF_HELPER_FLAGS_1(popcntd, TCG_CALL_NO_RWG_SE, tl, tl)
DEF_HELPER_3(srad, tl, env, tl, tl)
#endif

DEF_HELPER_FLAGS_1(cntlsw32, TCG_CALL_NO_RWG_SE, i32, i32)
DEF_HELPER_FLAGS_1(cntlzw32, TCG_CALL_NO_RWG_SE, i32, i32)
DEF_HELPER_FLAGS_2(brinc, TCG_CALL_NO_RWG_SE, tl, tl, tl)

DEF_HELPER_1(float_check_status, void, env)
DEF_HELPER_1(reset_fpstatus, void, env)
DEF_HELPER_3(compute_fprf, i32, env, i64, i32)
DEF_HELPER_3(store_fpscr, void, env, i64, i32)
DEF_HELPER_2(fpscr_clrbit, void, env, i32)
DEF_HELPER_2(fpscr_setbit, void, env, i32)
DEF_HELPER_2(float64_to_float32, i32, env, i64)
DEF_HELPER_2(float32_to_float64, i64, env, i32)

DEF_HELPER_4(fcmpo, void, env, i64, i64, i32)
DEF_HELPER_4(fcmpu, void, env, i64, i64, i32)

DEF_HELPER_2(fctiw, i64, env, i64)
DEF_HELPER_2(fctiwz, i64, env, i64)
#if defined(TARGET_PPC64)
DEF_HELPER_2(fcfid, i64, env, i64)
DEF_HELPER_2(fctid, i64, env, i64)
DEF_HELPER_2(fctidz, i64, env, i64)
#endif
DEF_HELPER_2(frsp, i64, env, i64)
DEF_HELPER_2(frin, i64, env, i64)
DEF_HELPER_2(friz, i64, env, i64)
DEF_HELPER_2(frip, i64, env, i64)
DEF_HELPER_2(frim, i64, env, i64)

DEF_HELPER_3(fadd, i64, env, i64, i64)
DEF_HELPER_3(fsub, i64, env, i64, i64)
DEF_HELPER_3(fmul, i64, env, i64, i64)
DEF_HELPER_3(fdiv, i64, env, i64, i64)
DEF_HELPER_4(fmadd, i64, env, i64, i64, i64)
DEF_HELPER_4(fmsub, i64, env, i64, i64, i64)
DEF_HELPER_4(fnmadd, i64, env, i64, i64, i64)
DEF_HELPER_4(fnmsub, i64, env, i64, i64, i64)
DEF_HELPER_2(fabs, i64, env, i64)
DEF_HELPER_2(fnabs, i64, env, i64)
DEF_HELPER_2(fneg, i64, env, i64)
DEF_HELPER_2(fsqrt, i64, env, i64)
DEF_HELPER_2(fre, i64, env, i64)
DEF_HELPER_2(fres, i64, env, i64)
DEF_HELPER_2(frsqrte, i64, env, i64)
DEF_HELPER_4(fsel, i64, env, i64, i64, i64)

#define dh_alias_avr ptr
#define dh_ctype_avr ppc_avr_t *
#define dh_is_signed_avr dh_is_signed_ptr

DEF_HELPER_3(vaddubm, void, avr, avr, avr)
DEF_HELPER_3(vadduhm, void, avr, avr, avr)
DEF_HELPER_3(vadduwm, void, avr, avr, avr)
DEF_HELPER_3(vsububm, void, avr, avr, avr)
DEF_HELPER_3(vsubuhm, void, avr, avr, avr)
DEF_HELPER_3(vsubuwm, void, avr, avr, avr)
DEF_HELPER_3(vavgub, void, avr, avr, avr)
DEF_HELPER_3(vavguh, void, avr, avr, avr)
DEF_HELPER_3(vavguw, void, avr, avr, avr)
DEF_HELPER_3(vavgsb, void, avr, avr, avr)
DEF_HELPER_3(vavgsh, void, avr, avr, avr)
DEF_HELPER_3(vavgsw, void, avr, avr, avr)
DEF_HELPER_3(vminsb, void, avr, avr, avr)
DEF_HELPER_3(vminsh, void, avr, avr, avr)
DEF_HELPER_3(vminsw, void, avr, avr, avr)
DEF_HELPER_3(vmaxsb, void, avr, avr, avr)
DEF_HELPER_3(vmaxsh, void, avr, avr, avr)
DEF_HELPER_3(vmaxsw, void, avr, avr, avr)
DEF_HELPER_3(vminub, void, avr, avr, avr)
DEF_HELPER_3(vminuh, void, avr, avr, avr)
DEF_HELPER_3(vminuw, void, avr, avr, avr)
DEF_HELPER_3(vmaxub, void, avr, avr, avr)
DEF_HELPER_3(vmaxuh, void, avr, avr, avr)
DEF_HELPER_3(vmaxuw, void, avr, avr, avr)
DEF_HELPER_4(vcmpequb, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpequh, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpequw, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpgtub, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpgtuh, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpgtuw, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpgtsb, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpgtsh, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpgtsw, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpeqfp, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpgefp, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpgtfp, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpbfp, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpequb_dot, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpequh_dot, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpequw_dot, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpgtub_dot, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpgtuh_dot, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpgtuw_dot, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpgtsb_dot, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpgtsh_dot, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpgtsw_dot, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpeqfp_dot, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpgefp_dot, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpgtfp_dot, void, env, avr, avr, avr)
DEF_HELPER_4(vcmpbfp_dot, void, env, avr, avr, avr)
DEF_HELPER_3(vmrglb, void, avr, avr, avr)
DEF_HELPER_3(vmrglh, void, avr, avr, avr)
DEF_HELPER_3(vmrglw, void, avr, avr, avr)
DEF_HELPER_3(vmrghb, void, avr, avr, avr)
DEF_HELPER_3(vmrghh, void, avr, avr, avr)
DEF_HELPER_3(vmrghw, void, avr, avr, avr)
DEF_HELPER_3(vmulesb, void, avr, avr, avr)
DEF_HELPER_3(vmulesh, void, avr, avr, avr)
DEF_HELPER_3(vmuleub, void, avr, avr, avr)
DEF_HELPER_3(vmuleuh, void, avr, avr, avr)
DEF_HELPER_3(vmulosb, void, avr, avr, avr)
DEF_HELPER_3(vmulosh, void, avr, avr, avr)
DEF_HELPER_3(vmuloub, void, avr, avr, avr)
DEF_HELPER_3(vmulouh, void, avr, avr, avr)
DEF_HELPER_3(vsrab, void, avr, avr, avr)
DEF_HELPER_3(vsrah, void, avr, avr, avr)
DEF_HELPER_3(vsraw, void, avr, avr, avr)
DEF_HELPER_3(vsrb, void, avr, avr, avr)
DEF_HELPER_3(vsrh, void, avr, avr, avr)
DEF_HELPER_3(vsrw, void, avr, avr, avr)
DEF_HELPER_3(vslb, void, avr, avr, avr)
DEF_HELPER_3(vslh, void, avr, avr, avr)
DEF_HELPER_3(vslw, void, avr, avr, avr)
DEF_HELPER_3(vslo, void, avr, avr, avr)
DEF_HELPER_3(vsro, void, avr, avr, avr)
DEF_HELPER_3(vaddcuw, void, avr, avr, avr)
DEF_HELPER_3(vsubcuw, void, avr, avr, avr)
DEF_HELPER_2(lvsl, void, avr, tl);
DEF_HELPER_2(lvsr, void, avr, tl);
DEF_HELPER_4(vaddsbs, void, env, avr, avr, avr)
DEF_HELPER_4(vaddshs, void, env, avr, avr, avr)
DEF_HELPER_4(vaddsws, void, env, avr, avr, avr)
DEF_HELPER_4(vsubsbs, void, env, avr, avr, avr)
DEF_HELPER_4(vsubshs, void, env, avr, avr, avr)
DEF_HELPER_4(vsubsws, void, env, avr, avr, avr)
DEF_HELPER_4(vaddubs, void, env, avr, avr, avr)
DEF_HELPER_4(vadduhs, void, env, avr, avr, avr)
DEF_HELPER_4(vadduws, void, env, avr, avr, avr)
DEF_HELPER_4(vsububs, void, env, avr, avr, avr)
DEF_HELPER_4(vsubuhs, void, env, avr, avr, avr)
DEF_HELPER_4(vsubuws, void, env, avr, avr, avr)
DEF_HELPER_3(vrlb, void, avr, avr, avr)
DEF_HELPER_3(vrlh, void, avr, avr, avr)
DEF_HELPER_3(vrlw, void, avr, avr, avr)
DEF_HELPER_3(vsl, void, avr, avr, avr)
DEF_HELPER_3(vsr, void, avr, avr, avr)
DEF_HELPER_4(vsldoi, void, avr, avr, avr, i32)
DEF_HELPER_2(vspltisb, void, avr, i32)
DEF_HELPER_2(vspltish, void, avr, i32)
DEF_HELPER_2(vspltisw, void, avr, i32)
DEF_HELPER_3(vspltb, void, avr, avr, i32)
DEF_HELPER_3(vsplth, void, avr, avr, i32)
DEF_HELPER_3(vspltw, void, avr, avr, i32)
DEF_HELPER_2(vupkhpx, void, avr, avr)
DEF_HELPER_2(vupklpx, void, avr, avr)
DEF_HELPER_2(vupkhsb, void, avr, avr)
DEF_HELPER_2(vupkhsh, void, avr, avr)
DEF_HELPER_2(vupklsb, void, avr, avr)
DEF_HELPER_2(vupklsh, void, avr, avr)
DEF_HELPER_5(vmsumubm, void, env, avr, avr, avr, avr)
DEF_HELPER_5(vmsummbm, void, env, avr, avr, avr, avr)
DEF_HELPER_5(vsel, void, env, avr, avr, avr, avr)
DEF_HELPER_5(vperm, void, env, avr, avr, avr, avr)
DEF_HELPER_4(vpkshss, void, env, avr, avr, avr)
DEF_HELPER_4(vpkshus, void, env, avr, avr, avr)
DEF_HELPER_4(vpkswss, void, env, avr, avr, avr)
DEF_HELPER_4(vpkswus, void, env, avr, avr, avr)
DEF_HELPER_4(vpkuhus, void, env, avr, avr, avr)
DEF_HELPER_4(vpkuwus, void, env, avr, avr, avr)
DEF_HELPER_4(vpkuhum, void, env, avr, avr, avr)
DEF_HELPER_4(vpkuwum, void, env, avr, avr, avr)
DEF_HELPER_3(vpkpx, void, avr, avr, avr)
DEF_HELPER_5(vmhaddshs, void, env, avr, avr, avr, avr)
DEF_HELPER_5(vmhraddshs, void, env, avr, avr, avr, avr)
DEF_HELPER_5(vmsumuhm, void, env, avr, avr, avr, avr)
DEF_HELPER_5(vmsumuhs, void, env, avr, avr, avr, avr)
DEF_HELPER_5(vmsumshm, void, env, avr, avr, avr, avr)
DEF_HELPER_5(vmsumshs, void, env, avr, avr, avr, avr)
DEF_HELPER_4(vmladduhm, void, avr, avr, avr, avr)
DEF_HELPER_2(mtvscr, void, env, avr);
DEF_HELPER_3(lvebx, void, env, avr, tl)
DEF_HELPER_3(lvehx, void, env, avr, tl)
DEF_HELPER_3(lvewx, void, env, avr, tl)
DEF_HELPER_3(stvebx, void, env, avr, tl)
DEF_HELPER_3(stvehx, void, env, avr, tl)
DEF_HELPER_3(stvewx, void, env, avr, tl)
DEF_HELPER_4(vsumsws, void, env, avr, avr, avr)
DEF_HELPER_4(vsum2sws, void, env, avr, avr, avr)
DEF_HELPER_4(vsum4sbs, void, env, avr, avr, avr)
DEF_HELPER_4(vsum4shs, void, env, avr, avr, avr)
DEF_HELPER_4(vsum4ubs, void, env, avr, avr, avr)
DEF_HELPER_4(vaddfp, void, env, avr, avr, avr)
DEF_HELPER_4(vsubfp, void, env, avr, avr, avr)
DEF_HELPER_4(vmaxfp, void, env, avr, avr, avr)
DEF_HELPER_4(vminfp, void, env, avr, avr, avr)
DEF_HELPER_3(vrefp, void, env, avr, avr)
DEF_HELPER_3(vrsqrtefp, void, env, avr, avr)
DEF_HELPER_5(vmaddfp, void, env, avr, avr, avr, avr)
DEF_HELPER_5(vnmsubfp, void, env, avr, avr, avr, avr)
DEF_HELPER_3(vexptefp, void, env, avr, avr)
DEF_HELPER_3(vlogefp, void, env, avr, avr)
DEF_HELPER_3(vrfim, void, env, avr, avr)
DEF_HELPER_3(vrfin, void, env, avr, avr)
DEF_HELPER_3(vrfip, void, env, avr, avr)
DEF_HELPER_3(vrfiz, void, env, avr, avr)
DEF_HELPER_4(vcfux, void, env, avr, avr, i32)
DEF_HELPER_4(vcfsx, void, env, avr, avr, i32)
DEF_HELPER_4(vctuxs, void, env, avr, avr, i32)
DEF_HELPER_4(vctsxs, void, env, avr, avr, i32)

DEF_HELPER_2(efscfsi, i32, env, i32)
DEF_HELPER_2(efscfui, i32, env, i32)
DEF_HELPER_2(efscfuf, i32, env, i32)
DEF_HELPER_2(efscfsf, i32, env, i32)
DEF_HELPER_2(efsctsi, i32, env, i32)
DEF_HELPER_2(efsctui, i32, env, i32)
DEF_HELPER_2(efsctsiz, i32, env, i32)
DEF_HELPER_2(efsctuiz, i32, env, i32)
DEF_HELPER_2(efsctsf, i32, env, i32)
DEF_HELPER_2(efsctuf, i32, env, i32)
DEF_HELPER_2(evfscfsi, i64, env, i64)
DEF_HELPER_2(evfscfui, i64, env, i64)
DEF_HELPER_2(evfscfuf, i64, env, i64)
DEF_HELPER_2(evfscfsf, i64, env, i64)
DEF_HELPER_2(evfsctsi, i64, env, i64)
DEF_HELPER_2(evfsctui, i64, env, i64)
DEF_HELPER_2(evfsctsiz, i64, env, i64)
DEF_HELPER_2(evfsctuiz, i64, env, i64)
DEF_HELPER_2(evfsctsf, i64, env, i64)
DEF_HELPER_2(evfsctuf, i64, env, i64)
DEF_HELPER_3(efsadd, i32, env, i32, i32)
DEF_HELPER_3(efssub, i32, env, i32, i32)
DEF_HELPER_3(efsmul, i32, env, i32, i32)
DEF_HELPER_3(efsdiv, i32, env, i32, i32)
DEF_HELPER_3(evfsadd, i64, env, i64, i64)
DEF_HELPER_3(evfssub, i64, env, i64, i64)
DEF_HELPER_3(evfsmul, i64, env, i64, i64)
DEF_HELPER_3(evfsdiv, i64, env, i64, i64)
DEF_HELPER_3(efststlt, i32, env, i32, i32)
DEF_HELPER_3(efststgt, i32, env, i32, i32)
DEF_HELPER_3(efststeq, i32, env, i32, i32)
DEF_HELPER_3(efscmplt, i32, env, i32, i32)
DEF_HELPER_3(efscmpgt, i32, env, i32, i32)
DEF_HELPER_3(efscmpeq, i32, env, i32, i32)
DEF_HELPER_3(evfststlt, i32, env, i64, i64)
DEF_HELPER_3(evfststgt, i32, env, i64, i64)
DEF_HELPER_3(evfststeq, i32, env, i64, i64)
DEF_HELPER_3(evfscmplt, i32, env, i64, i64)
DEF_HELPER_3(evfscmpgt, i32, env, i64, i64)
DEF_HELPER_3(evfscmpeq, i32, env, i64, i64)
DEF_HELPER_2(efdcfsi, i64, env, i32)
DEF_HELPER_2(efdcfsid, i64, env, i64)
DEF_HELPER_2(efdcfui, i64, env, i32)
DEF_HELPER_2(efdcfuid, i64, env, i64)
DEF_HELPER_2(efdctsi, i32, env, i64)
DEF_HELPER_2(efdctui, i32, env, i64)
DEF_HELPER_2(efdctsiz, i32, env, i64)
DEF_HELPER_2(efdctsidz, i64, env, i64)
DEF_HELPER_2(efdctuiz, i32, env, i64)
DEF_HELPER_2(efdctuidz, i64, env, i64)
DEF_HELPER_2(efdcfsf, i64, env, i32)
DEF_HELPER_2(efdcfuf, i64, env, i32)
DEF_HELPER_2(efdctsf, i32, env, i64)
DEF_HELPER_2(efdctuf, i32, env, i64)
DEF_HELPER_2(efscfd, i32, env, i64)
DEF_HELPER_2(efdcfs, i64, env, i32)
DEF_HELPER_3(efdadd, i64, env, i64, i64)
DEF_HELPER_3(efdsub, i64, env, i64, i64)
DEF_HELPER_3(efdmul, i64, env, i64, i64)
DEF_HELPER_3(efddiv, i64, env, i64, i64)
DEF_HELPER_3(efdtstlt, i32, env, i64, i64)
DEF_HELPER_3(efdtstgt, i32, env, i64, i64)
DEF_HELPER_3(efdtsteq, i32, env, i64, i64)
DEF_HELPER_3(efdcmplt, i32, env, i64, i64)
DEF_HELPER_3(efdcmpgt, i32, env, i64, i64)
DEF_HELPER_3(efdcmpeq, i32, env, i64, i64)

#if !defined(CONFIG_USER_ONLY)
DEF_HELPER_2(4xx_tlbre_hi, tl, env, tl)
DEF_HELPER_2(4xx_tlbre_lo, tl, env, tl)
DEF_HELPER_3(4xx_tlbwe_hi, void, env, tl, tl)
DEF_HELPER_3(4xx_tlbwe_lo, void, env, tl, tl)
DEF_HELPER_2(4xx_tlbsx, tl, env, tl)
DEF_HELPER_3(440_tlbre, tl, env, i32, tl)
DEF_HELPER_4(440_tlbwe, void, env, i32, tl, tl)
DEF_HELPER_2(440_tlbsx, tl, env, tl)
DEF_HELPER_1(booke206_tlbre, void, env)
DEF_HELPER_1(booke206_tlbwe, void, env)
DEF_HELPER_2(booke206_tlbsx, void, env, tl)
DEF_HELPER_2(booke206_tlbivax, void, env, tl)
DEF_HELPER_2(booke206_tlbilx0, void, env, tl)
DEF_HELPER_2(booke206_tlbilx1, void, env, tl)
DEF_HELPER_2(booke206_tlbilx3, void, env, tl)
DEF_HELPER_2(booke206_tlbflush, void, env, i32)
DEF_HELPER_3(booke_setpid, void, env, i32, tl)
DEF_HELPER_2(6xx_tlbd, void, env, tl)
DEF_HELPER_2(6xx_tlbi, void, env, tl)
DEF_HELPER_2(74xx_tlbd, void, env, tl)
DEF_HELPER_2(74xx_tlbi, void, env, tl)
DEF_HELPER_FLAGS_1(tlbia, TCG_CALL_NO_RWG, void, env)
DEF_HELPER_FLAGS_2(tlbie, TCG_CALL_NO_RWG, void, env, tl)
#if defined(TARGET_PPC64)
DEF_HELPER_FLAGS_3(store_slb, TCG_CALL_NO_RWG, void, env, tl, tl)
DEF_HELPER_2(load_slb_esid, tl, env, tl)
DEF_HELPER_2(load_slb_vsid, tl, env, tl)
DEF_HELPER_FLAGS_1(slbia, TCG_CALL_NO_RWG, void, env)
DEF_HELPER_FLAGS_2(slbie, TCG_CALL_NO_RWG, void, env, tl)
#endif
DEF_HELPER_FLAGS_2(load_sr, TCG_CALL_NO_RWG, tl, env, tl);
DEF_HELPER_FLAGS_3(store_sr, TCG_CALL_NO_RWG, void, env, tl, tl)

DEF_HELPER_FLAGS_1(602_mfrom, TCG_CALL_NO_RWG_SE, tl, tl)
DEF_HELPER_1(msgsnd, void, tl)
DEF_HELPER_2(msgclr, void, env, tl)
#endif

DEF_HELPER_4(dlmzb, tl, env, tl, tl, i32)
DEF_HELPER_FLAGS_2(clcs, TCG_CALL_NO_RWG_SE, tl, env, i32)
#if !defined(CONFIG_USER_ONLY)
DEF_HELPER_2(rac, tl, env, tl)
#endif
DEF_HELPER_3(div, tl, env, tl, tl)
DEF_HELPER_3(divo, tl, env, tl, tl)
DEF_HELPER_3(divs, tl, env, tl, tl)
DEF_HELPER_3(divso, tl, env, tl, tl)

DEF_HELPER_2(load_dcr, tl, env, tl);
DEF_HELPER_3(store_dcr, void, env, tl, tl)

DEF_HELPER_2(load_dump_spr, void, env, i32)
DEF_HELPER_2(store_dump_spr, void, env, i32)
DEF_HELPER_1(load_tbl, tl, env)
DEF_HELPER_1(load_tbu, tl, env)
DEF_HELPER_1(load_atbl, tl, env)
DEF_HELPER_1(load_atbu, tl, env)
DEF_HELPER_1(load_601_rtcl, tl, env)
DEF_HELPER_1(load_601_rtcu, tl, env)
#if !defined(CONFIG_USER_ONLY)
#if defined(TARGET_PPC64)
DEF_HELPER_2(store_asr, void, env, tl)
DEF_HELPER_1(load_purr, tl, env)
#endif
DEF_HELPER_2(store_sdr1, void, env, tl)
DEF_HELPER_2(store_tbl, void, env, tl)
DEF_HELPER_2(store_tbu, void, env, tl)
DEF_HELPER_2(store_atbl, void, env, tl)
DEF_HELPER_2(store_atbu, void, env, tl)
DEF_HELPER_2(store_601_rtcl, void, env, tl)
DEF_HELPER_2(store_601_rtcu, void, env, tl)
DEF_HELPER_1(load_decr, tl, env)
DEF_HELPER_2(store_decr, void, env, tl)
DEF_HELPER_2(store_hid0_601, void, env, tl)
DEF_HELPER_3(store_403_pbr, void, env, i32, tl)
DEF_HELPER_1(load_40x_pit, tl, env)
DEF_HELPER_2(store_40x_pit, void, env, tl)
DEF_HELPER_2(store_40x_dbcr0, void, env, tl)
DEF_HELPER_2(store_40x_sler, void, env, tl)
DEF_HELPER_2(store_booke_tcr, void, env, tl)
DEF_HELPER_2(store_booke_tsr, void, env, tl)
DEF_HELPER_3(store_ibatl, void, env, i32, tl)
DEF_HELPER_3(store_ibatu, void, env, i32, tl)
DEF_HELPER_3(store_dbatl, void, env, i32, tl)
DEF_HELPER_3(store_dbatu, void, env, i32, tl)
DEF_HELPER_3(store_601_batl, void, env, i32, tl)
DEF_HELPER_3(store_601_batu, void, env, i32, tl)
#endif

#include "exec/def-helper.h"
