/*
 *  AArch64 SVE specific helper definitions
 *
 *  Copyright (c) 2018 Linaro, Ltd
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

DEF_HELPER_FLAGS_2(sve_predtest1, TCG_CALL_NO_WG, i32, i64, i64)
DEF_HELPER_FLAGS_3(sve_predtest, TCG_CALL_NO_WG, i32, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(sve_pfirst, TCG_CALL_NO_WG, i32, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(sve_pnext, TCG_CALL_NO_WG, i32, ptr, ptr, i32)

DEF_HELPER_FLAGS_5(sve_and_zpzz_b, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_and_zpzz_h, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_and_zpzz_s, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_and_zpzz_d, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_5(sve_eor_zpzz_b, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_eor_zpzz_h, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_eor_zpzz_s, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_eor_zpzz_d, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_5(sve_orr_zpzz_b, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_orr_zpzz_h, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_orr_zpzz_s, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_orr_zpzz_d, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_5(sve_bic_zpzz_b, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_bic_zpzz_h, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_bic_zpzz_s, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_bic_zpzz_d, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_5(sve_add_zpzz_b, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_add_zpzz_h, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_add_zpzz_s, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_add_zpzz_d, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_5(sve_sub_zpzz_b, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_sub_zpzz_h, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_sub_zpzz_s, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_sub_zpzz_d, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_5(sve_smax_zpzz_b, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_smax_zpzz_h, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_smax_zpzz_s, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_smax_zpzz_d, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_5(sve_umax_zpzz_b, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_umax_zpzz_h, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_umax_zpzz_s, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_umax_zpzz_d, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_5(sve_smin_zpzz_b, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_smin_zpzz_h, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_smin_zpzz_s, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_smin_zpzz_d, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_5(sve_umin_zpzz_b, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_umin_zpzz_h, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_umin_zpzz_s, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_umin_zpzz_d, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_5(sve_sabd_zpzz_b, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_sabd_zpzz_h, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_sabd_zpzz_s, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_sabd_zpzz_d, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_5(sve_uabd_zpzz_b, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_uabd_zpzz_h, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_uabd_zpzz_s, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_uabd_zpzz_d, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_5(sve_mul_zpzz_b, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_mul_zpzz_h, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_mul_zpzz_s, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_mul_zpzz_d, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_5(sve_smulh_zpzz_b, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_smulh_zpzz_h, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_smulh_zpzz_s, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_smulh_zpzz_d, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_5(sve_umulh_zpzz_b, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_umulh_zpzz_h, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_umulh_zpzz_s, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_umulh_zpzz_d, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_5(sve_sdiv_zpzz_s, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_sdiv_zpzz_d, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_5(sve_udiv_zpzz_s, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_udiv_zpzz_d, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_5(sve_and_pppp, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_bic_pppp, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_eor_pppp, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_sel_pppp, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_orr_pppp, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_orn_pppp, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_nor_pppp, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_5(sve_nand_pppp, TCG_CALL_NO_RWG,
                   void, ptr, ptr, ptr, ptr, i32)
