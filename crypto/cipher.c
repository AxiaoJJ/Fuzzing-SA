/*
 * QEMU Crypto cipher algorithms
 *
 * Copyright (c) 2015 Red Hat, Inc.
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
 *
 */

#include "crypto/cipher.h"


static size_t alg_key_len[QCRYPTO_CIPHER_ALG_LAST] = {
    [QCRYPTO_CIPHER_ALG_AES_128] = 16,
    [QCRYPTO_CIPHER_ALG_AES_192] = 24,
    [QCRYPTO_CIPHER_ALG_AES_256] = 32,
    [QCRYPTO_CIPHER_ALG_DES_RFB] = 8,
};

static bool
qcrypto_cipher_validate_key_length(QCryptoCipherAlgorithm alg,
                                   size_t nkey,
                                   Error **errp)
{
    if ((unsigned)alg >= QCRYPTO_CIPHER_ALG_LAST) {
        error_setg(errp, "Cipher algorithm %d out of range",
                   alg);
        return false;
    }

    if (alg_key_len[alg] != nkey) {
        error_setg(errp, "Cipher key length %zu should be %zu",
                   alg_key_len[alg], nkey);
        return false;
    }
    return true;
}

#if defined(CONFIG_GNUTLS_GCRYPT)
static uint8_t *
qcrypto_cipher_munge_des_rfb_key(const uint8_t *key,
                                 size_t nkey)
{
    uint8_t *ret = g_new0(uint8_t, nkey);
    size_t i;
    for (i = 0; i < nkey; i++) {
        uint8_t r = key[i];
        r = (r & 0xf0) >> 4 | (r & 0x0f) << 4;
        r = (r & 0xcc) >> 2 | (r & 0x33) << 2;
        r = (r & 0xaa) >> 1 | (r & 0x55) << 1;
        ret[i] = r;
    }
    return ret;
}
#endif /* CONFIG_GNUTLS_GCRYPT */

#ifdef CONFIG_GNUTLS_GCRYPT
#include "crypto/cipher-gcrypt.c"
#else
#include "crypto/cipher-builtin.c"
#endif
