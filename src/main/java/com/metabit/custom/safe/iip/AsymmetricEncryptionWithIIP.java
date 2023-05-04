/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.iip;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.security.auth.DestroyFailedException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

/**
 * <p>AsymmetricEncryptionWithIIP interface.</p>
 *
 * interface to abstract IIP application with asymmetric cryptography.
 *
 * @author jwilkes
 * @version $Id: $Id
 */
public interface AsymmetricEncryptionWithIIP
{
    /**
     * <p>padEncryptAndPackage.</p>
     *
     * @param data an array of {@link byte} objects
     * @param otherSideECPublicKey a {@link java.security.PublicKey} object
     * @param ourECPrivateKey a {@link java.security.PrivateKey} object
     * @param keyDiversification an array of {@link byte} objects
     * @return an array of {@link byte} objects
     * @throws java.security.NoSuchAlgorithmException if any.
     * @throws java.security.InvalidKeyException if any.
     * @throws javax.crypto.IllegalBlockSizeException if any.
     * @throws javax.crypto.BadPaddingException if any.
     * @throws javax.security.auth.DestroyFailedException if any.
     * @throws java.security.spec.InvalidKeySpecException if any.
     * @throws javax.crypto.ShortBufferException if any.
     */
    byte[] padEncryptAndPackage(byte[] data, PublicKey otherSideECPublicKey, PrivateKey ourECPrivateKey, byte[] keyDiversification)
            throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            DestroyFailedException, InvalidKeySpecException, ShortBufferException;

    // variant with multiple recipients
    /**
     * <p>padEncryptAndPackage.</p>
     *
     * @param contentToSeal an array of {@link byte} objects
     * @param recipientKeys an array of {@link java.security.PublicKey} objects
     * @param senderKey a {@link java.security.PrivateKey} object
     * @param keyDiversificationForEC an array of {@link byte} objects
     * @return an array of {@link byte} objects
     * @throws java.security.NoSuchAlgorithmException if any.
     * @throws java.security.spec.InvalidKeySpecException if any.
     * @throws java.security.InvalidKeyException if any.
     * @throws javax.crypto.IllegalBlockSizeException if any.
     * @throws javax.crypto.BadPaddingException if any.
     * @throws javax.crypto.ShortBufferException if any.
     */
    byte[] padEncryptAndPackage(byte[] contentToSeal, PublicKey[] recipientKeys, PrivateKey senderKey, byte[] keyDiversificationForEC)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, ShortBufferException;

    /**
     * <p>decryptAndVerify.</p>
     *
     * @param encryptedData an array of {@link byte} objects
     * @param otherSideECPublicKey a {@link java.security.PublicKey} object
     * @param ourECPrivateKey a {@link java.security.PrivateKey} object
     * @param keyDiversificationForEC an array of {@link byte} objects
     * @param ivForSymmetricCrypto an array of {@link byte} objects
     * @return an array of {@link byte} objects
     * @throws java.security.NoSuchAlgorithmException if any.
     * @throws java.security.spec.InvalidKeySpecException if any.
     * @throws java.security.InvalidKeyException if any.
     * @throws java.security.InvalidAlgorithmParameterException if any.
     * @throws javax.crypto.IllegalBlockSizeException if any.
     * @throws javax.crypto.BadPaddingException if any.
     * @throws javax.crypto.ShortBufferException if any.
     */
    byte[] decryptAndVerify(byte[] encryptedData, PublicKey otherSideECPublicKey, PrivateKey ourECPrivateKey, byte[] keyDiversificationForEC, byte[] ivForSymmetricCrypto)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, ShortBufferException;

    /**
     * <p>getSymmetricIV.</p>
     *
     * @return an array of {@link byte} objects
     */
    byte[] getSymmetricIV();
}
