/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.iip;

import com.metabit.custom.safe.iip.shared.AlgorithmSpec;
import com.metabit.custom.safe.iip.shared.CryptoFactory;

import javax.crypto.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;

/**
 * <p>RSAWithIntegrityPadding class.</p>
 *
 * performs RSA/ECB/IIP, chaining provided by the IIP.
 *
 * Caveat: the MSB of an RSA block is unavailable, since it must be set;
 * some SecurityProvider implementations may chose to block a byte or more.
 * This implementation is compatible with the way BouncyCastle handles this.
 * Using a different SecurityProvider/JCE may cause issues with block size.
 * There's settings in the
 * @author jwilkes
 * @version $Id: $Id
 */
public class RSAWithIntegrityPadding implements AsymmetricEncryptionWithIIP
{
    private final CryptoFactory cf;
    private final AlgorithmSpec algorithmSpec;
    private final Cipher cipher;
    private final SecureRandom rng;
    private final InterleavedIntegrityPadding integrityPaddingInstance;

    /**
     * <p>Constructor for RSAWithIntegrityPadding.</p>
     *
     * @param cryptoFactory a {@link com.metabit.custom.safe.iip.shared.CryptoFactory} object
     * @param spec a {@link com.metabit.custom.safe.iip.shared.AlgorithmSpec} object
     * @throws java.security.NoSuchAlgorithmException if any.
     * @throws java.security.NoSuchProviderException if any.
     * @throws javax.crypto.NoSuchPaddingException if any.
     * @throws java.security.InvalidKeyException if any.
     */
    public RSAWithIntegrityPadding(CryptoFactory cryptoFactory, AlgorithmSpec spec)
            throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException
        {
        this.cf = cryptoFactory;
        this.algorithmSpec = spec;
        this.rng = new SecureRandom();

        cipher = cf.getCipherFromCipherSpec(algorithmSpec);
        integrityPaddingInstance = new InterleavedIntegrityPadding(algorithmSpec.getUsableBlockSize());
        }


    /**
     * <p>padEncryptAndPackage.</p>
     *
     * @param data               input payload data
     * @param otherSidePublicKey unused here
     * @param ourPrivateKey      the private key of this side, the sender
     * @param diversification    unused here
     * @return the result of both encryption processes.
     * @throws java.security.InvalidKeyException if key is invalid
     * @throws javax.crypto.IllegalBlockSizeException if the block size is invalid for key and algorithm chosen.
     * @throws javax.crypto.ShortBufferException if the output buffer is too small.
     * @throws javax.crypto.BadPaddingException if IIP fails.
     */
    public byte[] padEncryptAndPackage(final byte[] data, final PublicKey otherSidePublicKey, final PrivateKey ourPrivateKey, final byte[] diversification)
            throws InvalidKeyException, IllegalBlockSizeException, ShortBufferException, BadPaddingException
        {
        final int RSA_blocksize = algorithmSpec.getCipherBlockSize();
        int usable_blocksize = algorithmSpec.getUsableBlockSize();

        RSAPrivateKey rsaPrivKey = (RSAPrivateKey) ourPrivateKey; // cast checks for correct key type for the algorithms
        assert (rsaPrivKey.getModulus().bitLength() == algorithmSpec.getKeySizeInBit()); // must match expected size

        // pad
        byte[] padded = integrityPaddingInstance.performPaddingWithAllocation(data);
        assert (padded.length % usable_blocksize == 0); // if not, our padding has a bug

        // encrypt
        cipher.init(Cipher.ENCRYPT_MODE, ourPrivateKey, rng);
        // rsa will support single blocks only, so we have to split ourselves.
        int inputLength = padded.length;
        int outputLength = (inputLength / usable_blocksize) * RSA_blocksize; // scaling from one to the other
        byte[] encrypted = new byte[outputLength];
        int numBlocksInput = outputLength / RSA_blocksize;
        for (int i = 0; i < numBlocksInput; i++)
            {
            cipher.doFinal(padded, i * usable_blocksize, usable_blocksize, encrypted, i * RSA_blocksize); // different blocksizes. Details matter.
            }
        // cleanup as far as possible
        Arrays.fill(padded, (byte) 0x00);
        // return result
        return encrypted;
        }

    /** {@inheritDoc} */
    @Override
    public byte[] padEncryptAndPackage(final byte[] contentToSeal, final PublicKey[] recipientKeys, final PrivateKey senderKey, final byte[] keyDiversificationForEC)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, ShortBufferException
        {
        // recipient keys are ignored in RSA scheme.
        return padEncryptAndPackage(contentToSeal, (PublicKey) null, senderKey, null);
        }

    /**
     * <p>decryptAndVerify.</p>
     *
     * @param encryptedData       encrypted data to be decrypted
     * @param senderPublicKey     public key of the sender. required, used for authentication and decryption.
     * @param recipientPrivateKey optional for RSA
     * @param diversification     unused with RSA
     * @param iv                  unused with RSA
     * @return an array of {@link byte} plaintext payload unwrapped from the padded data.
     * @throws java.security.InvalidKeyException if key is invalid
     * @throws javax.crypto.IllegalBlockSizeException if the block size is invalid for key and algorithm chosen.
     * @throws javax.crypto.ShortBufferException if the output buffer is too small.
     * @throws javax.crypto.BadPaddingException if IIP detects an integrity violation. This is the main thing to check for.
     */
    public byte[] decryptAndVerify(final byte[] encryptedData, final PublicKey senderPublicKey, final PrivateKey recipientPrivateKey, final byte[] diversification, final byte[] iv)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, ShortBufferException
        {
        final int RSA_blocksize = algorithmSpec.getCipherBlockSize();
        int usable_blocksize = algorithmSpec.getUsableBlockSize();

        if (encryptedData.length % RSA_blocksize != 0)
            throw new IllegalArgumentException("input length doesn't fit with key size");

        int numBlocks = encryptedData.length / RSA_blocksize; // because of previous check, this is clean
        int decryptedLength = encryptedData.length; // same

        byte[] decrypted = new byte[numBlocks * usable_blocksize];

        // decrypt
        cipher.init(Cipher.DECRYPT_MODE, senderPublicKey, rng);
        // we're to process the blocks ourselves.
        int i = numBlocks;
        int inputOffset = 0;
        int outputOffset = 0;
        while (i > 0)
            {
            cipher.doFinal(encryptedData, inputOffset, RSA_blocksize, decrypted, outputOffset);
            inputOffset += RSA_blocksize;
            outputOffset += usable_blocksize;
            i--;
            }

        // now validate padding and extract payload
        byte[] payload = integrityPaddingInstance.checkAndExtract(decrypted);
        // cleanup as far as possible
        Arrays.fill(decrypted, (byte) 0x00);
        // return result
        return payload;
        }

    // not used with RSA
    /**
     * <p>getSymmetricIV.</p>
     *
     * @return an array of {@link byte} objects
     */
    public byte[] getSymmetricIV()
        {
        return null;
        }

}
//___EOF___
