/*
 * QEMU Crypto block IV generator
 *
 * Copyright (c) 2015-2016 Red Hat, Inc.
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

#ifndef QCRYPTO_IVGEN_H
#define QCRYPTO_IVGEN_H

#include "crypto/cipher.h"
#include "crypto/hash.h"

/**
 * This module provides a framework for generating initialization
 * vectors for block encryption schemes using chained cipher modes
 * CBC. The principle is that each disk sector is assigned a unique
 * initialization vector for use for encryption of data in that
 * sector.
 *
 * <example>
 *   <title>Encrypting block data with initialiation vectors</title>
 *   <programlisting>
 * uint8_t *data = ....data to encrypt...
 * size_t ndata = XXX;
 * uint8_t *key = ....some encryption key...
 * size_t nkey = XXX;
 * uint8_t *iv;
 * size_t niv;
 * size_t sector = 0;
 *
 * g_assert((ndata % 512) == 0);
 *
 * QCryptoIVGen *ivgen = qcrypto_ivgen_new(QCRYPTO_IVGEN_ALG_ESSIV,
 *                                         QCRYPTO_CIPHER_ALG_AES_128,
 *                                         QCRYPTO_HASH_ALG_SHA256,
 *                                         key, nkey, errp);
 * if (!ivgen) {
 *    return -1;
 * }
 *
 * QCryptoCipher *cipher = qcrypto_cipher_new(QCRYPTO_CIPHER_ALG_AES_128,
 *                                            QCRYPTO_CIPHER_MODE_CBC,
 *                                            key, nkey, errp);
 * if (!cipher) {
 *     goto error;
 * }
 *
 * niv =  qcrypto_cipher_get_iv_len(QCRYPTO_CIPHER_ALG_AES_128,
 *                                  QCRYPTO_CIPHER_MODE_CBC);
 * iv = g_new0(uint8_t, niv);
 *
 *
 * while (ndata) {
 *     if (qcrypto_ivgen_calculate(ivgen, sector, iv, niv, errp) < 0) {
 *         goto error;
 *     }
 *     if (qcrypto_cipher_setiv(cipher, iv, niv, errp) < 0) {
 *         goto error;
 *     }
 *     if (qcrypto_cipher_encrypt(cipher,
 *                                data + (sector * 512),
 *                                data + (sector * 512),
 *                                512, errp) < 0) {
 *         goto error;
 *     }
 *     sector++;
 *     ndata -= 512;
 * }
 *
 * g_free(iv);
 * qcrypto_ivgen_free(ivgen);
 * qcrypto_cipher_free(cipher);
 * return 0;
 *
 *error:
 * g_free(iv);
 * qcrypto_ivgen_free(ivgen);
 * qcrypto_cipher_free(cipher);
 * return -1;
 *   </programlisting>
 * </example>
 */

typedef struct QCryptoIVGen QCryptoIVGen;

/* See also QCryptoIVGenAlgorithm enum in qapi/crypto.json */


/**
 * qcrypto_ivgen_new:
 * @alg: the initialization vector generation algorithm
 * @cipheralg: the cipher algorithm or 0
 * @hash: the hash algorithm or 0
 * @key: the encryption key or NULL
 * @nkey: the size of @key in bytes
 *
 * Create a new initialization vector generator that uses
 * the algorithm @alg. Whether the remaining parameters
 * are required or not depends on the choice of @alg
 * requested.
 *
 * - QCRYPTO_IVGEN_ALG_PLAIN
 *
 * The IVs are generated by the 32-bit truncated sector
 * number. This should never be used for block devices
 * that are larger than 2^32 sectors in size.
 * All the other parameters are unused.
 *
 * - QCRYPTO_IVGEN_ALG_PLAIN64
 *
 * The IVs are generated by the 64-bit sector number.
 * All the other parameters are unused.
 *
 * - QCRYPTO_IVGEN_ALG_ESSIV:
 *
 * The IVs are generated by encrypting the 64-bit sector
 * number with a hash of an encryption key. The @cipheralg,
 * @hash, @key and @nkey parameters are all required.
 *
 * Returns: a new IV generator, or NULL on error
 */
QCryptoIVGen *qcrypto_ivgen_new(QCryptoIVGenAlgorithm alg,
                                QCryptoCipherAlgorithm cipheralg,
                                QCryptoHashAlgorithm hash,
                                const uint8_t *key, size_t nkey,
                                Error **errp);

/**
 * qcrypto_ivgen_calculate:
 * @ivgen: the IV generator object
 * @sector: the 64-bit sector number
 * @iv: a pre-allocated buffer to hold the generated IV
 * @niv: the number of bytes in @iv
 * @errp: pointer to a NULL-initialized error object
 *
 * Calculate a new initialiation vector for the data
 * to be stored in sector @sector. The IV will be
 * written into the buffer @iv of size @niv.
 *
 * Returns: 0 on success, -1 on error
 */
int qcrypto_ivgen_calculate(QCryptoIVGen *ivgen,
                            uint64_t sector,
                            uint8_t *iv, size_t niv,
                            Error **errp);


/**
 * qcrypto_ivgen_get_algorithm:
 * @ivgen: the IV generator object
 *
 * Get the algorithm used by this IV generator
 *
 * Returns: the IV generator algorithm
 */
QCryptoIVGenAlgorithm qcrypto_ivgen_get_algorithm(QCryptoIVGen *ivgen);


/**
 * qcrypto_ivgen_get_cipher:
 * @ivgen: the IV generator object
 *
 * Get the cipher algorithm used by this IV generator (if
 * applicable)
 *
 * Returns: the cipher algorithm
 */
QCryptoCipherAlgorithm qcrypto_ivgen_get_cipher(QCryptoIVGen *ivgen);


/**
 * qcrypto_ivgen_get_hash:
 * @ivgen: the IV generator object
 *
 * Get the hash algorithm used by this IV generator (if
 * applicable)
 *
 * Returns: the hash algorithm
 */
QCryptoHashAlgorithm qcrypto_ivgen_get_hash(QCryptoIVGen *ivgen);


/**
 * qcrypto_ivgen_free:
 * @ivgen: the IV generator object
 *
 * Release all resources associated with @ivgen, or a no-op
 * if @ivgen is NULL
 */
void qcrypto_ivgen_free(QCryptoIVGen *ivgen);

#endif /* QCRYPTO_IVGEN_H */
