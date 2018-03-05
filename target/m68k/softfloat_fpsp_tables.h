/*
 * Ported from a work by Andreas Grabher for Previous, NeXT Computer Emulator,
 * derived from NetBSD M68040 FPSP functions,
 * derived from release 2a of the SoftFloat IEC/IEEE Floating-point Arithmetic
 * Package. Those parts of the code (and some later contributions) are
 * provided under that license, as detailed below.
 * It has subsequently been modified by contributors to the QEMU Project,
 * so some portions are provided under:
 *  the SoftFloat-2a license
 *  the BSD license
 *  GPL-v2-or-later
 *
 * Any future contributions to this file will be taken to be licensed under
 * the Softfloat-2a license unless specifically indicated otherwise.
 */

/* Portions of this work are licensed under the terms of the GNU GPL,
 * version 2 or later. See the COPYING file in the top-level directory.
 */

#ifndef TARGET_M68K_SOFTFLOAT_FPSP_TABLES_H
#define TARGET_M68K_SOFTFLOAT_FPSP_TABLES_H

static const floatx80 log_tbl[128] = {
    make_floatx80_init(0x3FFE, 0xFE03F80FE03F80FE),
    make_floatx80_init(0x3FF7, 0xFF015358833C47E2),
    make_floatx80_init(0x3FFE, 0xFA232CF252138AC0),
    make_floatx80_init(0x3FF9, 0xBDC8D83EAD88D549),
    make_floatx80_init(0x3FFE, 0xF6603D980F6603DA),
    make_floatx80_init(0x3FFA, 0x9CF43DCFF5EAFD48),
    make_floatx80_init(0x3FFE, 0xF2B9D6480F2B9D65),
    make_floatx80_init(0x3FFA, 0xDA16EB88CB8DF614),
    make_floatx80_init(0x3FFE, 0xEF2EB71FC4345238),
    make_floatx80_init(0x3FFB, 0x8B29B7751BD70743),
    make_floatx80_init(0x3FFE, 0xEBBDB2A5C1619C8C),
    make_floatx80_init(0x3FFB, 0xA8D839F830C1FB49),
    make_floatx80_init(0x3FFE, 0xE865AC7B7603A197),
    make_floatx80_init(0x3FFB, 0xC61A2EB18CD907AD),
    make_floatx80_init(0x3FFE, 0xE525982AF70C880E),
    make_floatx80_init(0x3FFB, 0xE2F2A47ADE3A18AF),
    make_floatx80_init(0x3FFE, 0xE1FC780E1FC780E2),
    make_floatx80_init(0x3FFB, 0xFF64898EDF55D551),
    make_floatx80_init(0x3FFE, 0xDEE95C4CA037BA57),
    make_floatx80_init(0x3FFC, 0x8DB956A97B3D0148),
    make_floatx80_init(0x3FFE, 0xDBEB61EED19C5958),
    make_floatx80_init(0x3FFC, 0x9B8FE100F47BA1DE),
    make_floatx80_init(0x3FFE, 0xD901B2036406C80E),
    make_floatx80_init(0x3FFC, 0xA9372F1D0DA1BD17),
    make_floatx80_init(0x3FFE, 0xD62B80D62B80D62C),
    make_floatx80_init(0x3FFC, 0xB6B07F38CE90E46B),
    make_floatx80_init(0x3FFE, 0xD3680D3680D3680D),
    make_floatx80_init(0x3FFC, 0xC3FD032906488481),
    make_floatx80_init(0x3FFE, 0xD0B69FCBD2580D0B),
    make_floatx80_init(0x3FFC, 0xD11DE0FF15AB18CA),
    make_floatx80_init(0x3FFE, 0xCE168A7725080CE1),
    make_floatx80_init(0x3FFC, 0xDE1433A16C66B150),
    make_floatx80_init(0x3FFE, 0xCB8727C065C393E0),
    make_floatx80_init(0x3FFC, 0xEAE10B5A7DDC8ADD),
    make_floatx80_init(0x3FFE, 0xC907DA4E871146AD),
    make_floatx80_init(0x3FFC, 0xF7856E5EE2C9B291),
    make_floatx80_init(0x3FFE, 0xC6980C6980C6980C),
    make_floatx80_init(0x3FFD, 0x82012CA5A68206D7),
    make_floatx80_init(0x3FFE, 0xC4372F855D824CA6),
    make_floatx80_init(0x3FFD, 0x882C5FCD7256A8C5),
    make_floatx80_init(0x3FFE, 0xC1E4BBD595F6E947),
    make_floatx80_init(0x3FFD, 0x8E44C60B4CCFD7DE),
    make_floatx80_init(0x3FFE, 0xBFA02FE80BFA02FF),
    make_floatx80_init(0x3FFD, 0x944AD09EF4351AF6),
    make_floatx80_init(0x3FFE, 0xBD69104707661AA3),
    make_floatx80_init(0x3FFD, 0x9A3EECD4C3EAA6B2),
    make_floatx80_init(0x3FFE, 0xBB3EE721A54D880C),
    make_floatx80_init(0x3FFD, 0xA0218434353F1DE8),
    make_floatx80_init(0x3FFE, 0xB92143FA36F5E02E),
    make_floatx80_init(0x3FFD, 0xA5F2FCABBBC506DA),
    make_floatx80_init(0x3FFE, 0xB70FBB5A19BE3659),
    make_floatx80_init(0x3FFD, 0xABB3B8BA2AD362A5),
    make_floatx80_init(0x3FFE, 0xB509E68A9B94821F),
    make_floatx80_init(0x3FFD, 0xB1641795CE3CA97B),
    make_floatx80_init(0x3FFE, 0xB30F63528917C80B),
    make_floatx80_init(0x3FFD, 0xB70475515D0F1C61),
    make_floatx80_init(0x3FFE, 0xB11FD3B80B11FD3C),
    make_floatx80_init(0x3FFD, 0xBC952AFEEA3D13E1),
    make_floatx80_init(0x3FFE, 0xAF3ADDC680AF3ADE),
    make_floatx80_init(0x3FFD, 0xC2168ED0F458BA4A),
    make_floatx80_init(0x3FFE, 0xAD602B580AD602B6),
    make_floatx80_init(0x3FFD, 0xC788F439B3163BF1),
    make_floatx80_init(0x3FFE, 0xAB8F69E28359CD11),
    make_floatx80_init(0x3FFD, 0xCCECAC08BF04565D),
    make_floatx80_init(0x3FFE, 0xA9C84A47A07F5638),
    make_floatx80_init(0x3FFD, 0xD24204872DD85160),
    make_floatx80_init(0x3FFE, 0xA80A80A80A80A80B),
    make_floatx80_init(0x3FFD, 0xD78949923BC3588A),
    make_floatx80_init(0x3FFE, 0xA655C4392D7B73A8),
    make_floatx80_init(0x3FFD, 0xDCC2C4B49887DACC),
    make_floatx80_init(0x3FFE, 0xA4A9CF1D96833751),
    make_floatx80_init(0x3FFD, 0xE1EEBD3E6D6A6B9E),
    make_floatx80_init(0x3FFE, 0xA3065E3FAE7CD0E0),
    make_floatx80_init(0x3FFD, 0xE70D785C2F9F5BDC),
    make_floatx80_init(0x3FFE, 0xA16B312EA8FC377D),
    make_floatx80_init(0x3FFD, 0xEC1F392C5179F283),
    make_floatx80_init(0x3FFE, 0x9FD809FD809FD80A),
    make_floatx80_init(0x3FFD, 0xF12440D3E36130E6),
    make_floatx80_init(0x3FFE, 0x9E4CAD23DD5F3A20),
    make_floatx80_init(0x3FFD, 0xF61CCE92346600BB),
    make_floatx80_init(0x3FFE, 0x9CC8E160C3FB19B9),
    make_floatx80_init(0x3FFD, 0xFB091FD38145630A),
    make_floatx80_init(0x3FFE, 0x9B4C6F9EF03A3CAA),
    make_floatx80_init(0x3FFD, 0xFFE97042BFA4C2AD),
    make_floatx80_init(0x3FFE, 0x99D722DABDE58F06),
    make_floatx80_init(0x3FFE, 0x825EFCED49369330),
    make_floatx80_init(0x3FFE, 0x9868C809868C8098),
    make_floatx80_init(0x3FFE, 0x84C37A7AB9A905C9),
    make_floatx80_init(0x3FFE, 0x97012E025C04B809),
    make_floatx80_init(0x3FFE, 0x87224C2E8E645FB7),
    make_floatx80_init(0x3FFE, 0x95A02568095A0257),
    make_floatx80_init(0x3FFE, 0x897B8CAC9F7DE298),
    make_floatx80_init(0x3FFE, 0x9445809445809446),
    make_floatx80_init(0x3FFE, 0x8BCF55DEC4CD05FE),
    make_floatx80_init(0x3FFE, 0x92F113840497889C),
    make_floatx80_init(0x3FFE, 0x8E1DC0FB89E125E5),
    make_floatx80_init(0x3FFE, 0x91A2B3C4D5E6F809),
    make_floatx80_init(0x3FFE, 0x9066E68C955B6C9B),
    make_floatx80_init(0x3FFE, 0x905A38633E06C43B),
    make_floatx80_init(0x3FFE, 0x92AADE74C7BE59E0),
    make_floatx80_init(0x3FFE, 0x8F1779D9FDC3A219),
    make_floatx80_init(0x3FFE, 0x94E9BFF615845643),
    make_floatx80_init(0x3FFE, 0x8DDA520237694809),
    make_floatx80_init(0x3FFE, 0x9723A1B720134203),
    make_floatx80_init(0x3FFE, 0x8CA29C046514E023),
    make_floatx80_init(0x3FFE, 0x995899C890EB8990),
    make_floatx80_init(0x3FFE, 0x8B70344A139BC75A),
    make_floatx80_init(0x3FFE, 0x9B88BDAA3A3DAE2F),
    make_floatx80_init(0x3FFE, 0x8A42F8705669DB46),
    make_floatx80_init(0x3FFE, 0x9DB4224FFFE1157C),
    make_floatx80_init(0x3FFE, 0x891AC73AE9819B50),
    make_floatx80_init(0x3FFE, 0x9FDADC268B7A12DA),
    make_floatx80_init(0x3FFE, 0x87F78087F78087F8),
    make_floatx80_init(0x3FFE, 0xA1FCFF17CE733BD4),
    make_floatx80_init(0x3FFE, 0x86D905447A34ACC6),
    make_floatx80_init(0x3FFE, 0xA41A9E8F5446FB9F),
    make_floatx80_init(0x3FFE, 0x85BF37612CEE3C9B),
    make_floatx80_init(0x3FFE, 0xA633CD7E6771CD8B),
    make_floatx80_init(0x3FFE, 0x84A9F9C8084A9F9D),
    make_floatx80_init(0x3FFE, 0xA8489E600B435A5E),
    make_floatx80_init(0x3FFE, 0x839930523FBE3368),
    make_floatx80_init(0x3FFE, 0xAA59233CCCA4BD49),
    make_floatx80_init(0x3FFE, 0x828CBFBEB9A020A3),
    make_floatx80_init(0x3FFE, 0xAC656DAE6BCC4985),
    make_floatx80_init(0x3FFE, 0x81848DA8FAF0D277),
    make_floatx80_init(0x3FFE, 0xAE6D8EE360BB2468),
    make_floatx80_init(0x3FFE, 0x8080808080808081),
    make_floatx80_init(0x3FFE, 0xB07197A23C46C654)
};
#endif
