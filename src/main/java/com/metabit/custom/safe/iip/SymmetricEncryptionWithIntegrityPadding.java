/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.iip;

import com.metabit.custom.safe.iip.shared.CryptoFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Arrays;

/**
 * <p>SymmetricEncryptionWithIntegrityPadding class.</p>
 *
 * This is the core implementation of IIP.
 *
 * @author jwilkes, metabit
 * @version $Id: $Id
 */
public class SymmetricEncryptionWithIntegrityPadding
{
    static final String[] CHAINING_WITHOUT_DIFFUSION = {"CFB", "OFB", "CTR", "GCM"};
    private SecureRandom rng;
    private Cipher cipher;
    private int                         cipherBlockSize;
    private InterleavedIntegrityPadding integrityPaddingInstance;

    /**
     * <p>Constructor for SymmetricEncryptionWithIntegrityPadding.</p>
     *
     * @param cipher a {@link javax.crypto.Cipher} encryption cipher handle
     * @param cryptoFactory a {@link CryptoFactory} cryptoFactory handle
     * @throws java.security.InvalidKeyException if key is invalid
     */
    public SymmetricEncryptionWithIntegrityPadding(Cipher cipher, final CryptoFactory cryptoFactory)
            throws InvalidKeyException
    {
        // safety check for "bad" chaining. will not catch all bad ones, but the most common-
        String cipherSpec = cipher.getAlgorithm();
        if (Arrays.stream(CHAINING_WITHOUT_DIFFUSION).anyMatch(cipherSpec::contains))
            throw new IllegalArgumentException("NEVER use streaming ciphers which just XOR their stream in combination with this padding!");
        int blockSize = cipher.getBlockSize();
        // later implementations may lift this restriction. It is "just" about making sure every block gets a nonce.
        if (blockSize !=  16)
            throw new UnsupportedOperationException("this implementation is optimised for blocksize 16");
        // current implementation is tuned for an extra block at start
        init(cipher);
    }


    private void init(Cipher cipher) throws InvalidKeyException
        {
        this.cipherBlockSize = cipher.getBlockSize();
        this.cipher = cipher;
        this.integrityPaddingInstance = new InterleavedIntegrityPadding(cipherBlockSize);
        this.rng = new SecureRandom();
        //@IMPROVEMENT dynamic IV size, according to cipher?
        }

    byte[] encryptOnly(final byte[] dataToEncrypt, final SecretKey secretKey)
            throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException
        {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, rng); // will create its own iv, and we have to retrieve it later with cipher.getIV();
        return cipher.doFinal(dataToEncrypt);
        }

    //------------------------------------------------------------------------------------------------------------------

    /**
     * <p>padAndEncrypt.</p>
     *
     * @param input an array of {@link byte} objects
     * @param secretKey a {@link javax.crypto.SecretKey} object
     * @return an array of {@link byte} objects
     * @throws javax.crypto.IllegalBlockSizeException if any.
     * @throws javax.crypto.BadPaddingException if any.
     * @throws java.security.InvalidKeyException if any.
     */
    public byte[] padAndEncrypt(final byte[] input, final SecretKey secretKey)
            throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException
        {
        byte[] padded = integrityPaddingInstance.performPaddingWithAllocation(input);
        return encryptOnly(padded, secretKey);
        }
    /**
     * <p>getIV.</p>
     *
     * @return an array of {@link byte} objects
     */
    public byte[] getIV()
        {
        return cipher.getIV();
        }

    //---

    /**
     * <p>decryptAndCheck.</p>
     *
     * @param input an array of {@link byte} objects
     * @param secretKey a {@link javax.crypto.SecretKey} object
     * @param iv an array of {@link byte} objects
     * @return an array of {@link byte} objects
     * @throws java.security.InvalidKeyException if any.
     * @throws java.security.InvalidAlgorithmParameterException if any.
     * @throws javax.crypto.IllegalBlockSizeException if any.
     * @throws javax.crypto.BadPaddingException if any.
     */
    public byte[] decryptAndCheck(final byte[] input, final SecretKey secretKey, byte[] iv)
            throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
                   BadPaddingException
        {
        if (iv != null)
            {
            final IvParameterSpec ivPS = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivPS); // will create its own iv, and we have to retrieve it later with cipher.getIV();
            }
        else
            {
            cipher.init(Cipher.DECRYPT_MODE,secretKey);
            }
        byte[] decryptedData = cipher.doFinal(input);
        byte[] payloadData = integrityPaddingInstance.checkAndExtract(decryptedData);
        return payloadData;
        }

    /**
     * <p>getAlgorithm.</p>
     *
     * @return a {@link java.lang.String} object
     */
    public String getAlgorithm()
        { return this.cipher.getAlgorithm(); }
}
//___EOF___

