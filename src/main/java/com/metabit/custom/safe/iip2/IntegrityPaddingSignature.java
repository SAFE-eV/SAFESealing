/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 licence.
 */
package com.metabit.custom.safe.iip2;

import com.metabit.custom.safe.iip.shared.AlgorithmSpec;
import com.metabit.custom.safe.iip.shared.CryptoFactory;
import com.metabit.custom.safe.safeseal.impl.CryptoSettingsStruct;
import lombok.NonNull;
import org.bouncycastle.crypto.DataLengthException;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;


/**
 * IPS, the second version to IIP.
 * padding, 2 AES forward, 1 AES backward, 1 RSA.
 *
 * References IPS paper, Signature Scheme. All references "C4" refer to "Construction 4 (Integrity Padding Signature Scheme ΣIPS )" in said paper.
 *
 */
public final class IntegrityPaddingSignature
{
    // constant Ck
    final static  byte[]          MAGIC_ID        = {0x3E, 0x7A, (byte) 0xB1, 0x70, 0x5A, (byte) 0xFE, (byte) 0xE4, 0x21, (byte) 0xEA, 0x41, (byte) 0x94, (byte) 0xE4, 0x04, 0x07, 0x07, (byte) 0xEA};
    // 0x 3E7A B170 5AFE E421 EA41 94E4 0407 07EA
    static final  int             LENGTH_SIZE     = 4; // 32 bit unsigned integer representation
    static final  int             SEQUENCE_SIZE   = 4; // 32 bit unsigned integer representation
    final private int             RSA_PREFIX_SIZE = 2;
    private final SecureRandom    rng;
    private final IvParameterSpec constantSK1IV;
    private final IvParameterSpec constantSK2IV;
    private final IvParameterSpec constantSK3IV;
    private final Cipher          symmetricCipher;
    private final Cipher          asymmetricCipher;
    private final AlgorithmSpec   asymmetricEncryptionSpec;
    private final int             innerBlockSize;
    private final int             nonceSize;     // for fixed symmetric algorithm, constant
    //     static final        int             NONCE_SIZE = 8; // when AES is given

    private final int headerSize;    // for fixed symmetric algorithm, constant
    //    public static final int             HEADER_SIZE     = MAGIC_ID.length+NONCE_SIZE+LENGTH_SIZE+SEQUENCE_SIZE;
    private final int outerBlockSize;
    private final int numPayloadBytesPerOuterBlock;

    /**
     * constructor
     *
     * @param cf  the CryptoFactory providing access to algorithm implementations
     * @param css the structure containing the settings in use for this instance
     * @throws NoSuchPaddingException   entry specified in the settings not found/defined
     * @throws NoSuchAlgorithmException entry specified in the settings not found/defined
     * @throws NoSuchProviderException  crypto provider specified by implementation not available
     */
    public IntegrityPaddingSignature(CryptoFactory cf, final CryptoSettingsStruct css)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException
        {
        this.rng = new SecureRandom();
        /* code for fixed implementation:
        asymmetric = cf.getCipherFromCipherSpec(AlgorithmSpecCollection.RSA2048);
        symmetric = cf.getCipherFromCipherSpec(AlgorithmSpecCollection.AES256CBC);
        int sBlockSize = 16;
        */
        asymmetricEncryptionSpec = css.getEncryption();
        asymmetricCipher = cf.getCipherFromCipherSpec(asymmetricEncryptionSpec);
        AlgorithmSpec symmetricEncryptionSpec = css.getSig1();
        symmetricCipher = cf.getCipherFromCipherSpec(symmetricEncryptionSpec);
        innerBlockSize = symmetricEncryptionSpec.getUsableBlockSize(); // for AES, this is 16. see C4.1 l_IC
        outerBlockSize = SharedCode.outerBlockSize(css); // for RSA, this depends on the key size. see C4.1 l_RSA
        // if (outerBlockSize % innerBlockSize != 0)
        //      throw new BadPaddingException(); -- implicit condition, see RSA details below.
        nonceSize = innerBlockSize-(LENGTH_SIZE+SEQUENCE_SIZE);
        headerSize = MAGIC_ID.length+nonceSize+LENGTH_SIZE+SEQUENCE_SIZE;
        numPayloadBytesPerOuterBlock = outerBlockSize-headerSize; // pre-calculated as well. see C4.1, "l"
        // init constant IVs
        byte[] iv = new byte[innerBlockSize];
        // all 0x00
        constantSK1IV = new IvParameterSpec(iv);
        iv[0] = 0x40;
        constantSK2IV = new IvParameterSpec(iv);
        iv[0] = (byte) 0x80;
        constantSK3IV = new IvParameterSpec(iv);
        }


    /**
     * perform protection process using encryption.
     *
     * @param plaintext        payload data to be protected, "m"
     * @param senderPrivateKey private key of the sender, secret
     * @param sig2SK1          symmetric key 1, shared; C4.2(a)
     * @param sig2SK2          symmetric key 2, shared; C4.2(a)
     * @param sig2SK3          symmetric key 3, shared; C4.2(a)
     * @return protected data
     *
     * @throws InvalidKeyException                key parameter invalid
     * @throws InvalidAlgorithmParameterException error in algorithm constants
     * @throws IllegalBlockSizeException          implementation error
     * @throws BadPaddingException                implementation error
     * @throws ShortBufferException               implementation error
     */
    public byte[] performEncryption(final byte[] plaintext, final PrivateKey senderPrivateKey, final Key sig2SK1, final Key sig2SK2, final Key sig2SK3)
            throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException, ShortBufferException // , parameters
        {
        // guard clauses
        if ((plaintext == null) || (senderPrivateKey == null) || (sig2SK1 == null) || (sig2SK2 == null) || (sig2SK3 == null))
            throw new IllegalArgumentException("parameters must not be null");

        // plaintext must not be longer than (2^32)-1 = 0xFFFFFFFF. (see C4.1, by message space definition)
        // In Java, this implicitly guaranteed by JRE. "int MAX_ARRAY_SIZE = Integer.MAX_VALUE - 8;" in JRE/JDK source.
        int plaintextLength = plaintext.length;

        // calculate operation buffer size.
        // numPayloadBytesPerOuterBlock = outerBlockSize-HEADER_SIZE; -- performed in constructor upon knowledge of key size

        // calculate number of blocks: divide and round up
        int numPayloadBlocks = (plaintextLength+numPayloadBytesPerOuterBlock-1)/numPayloadBytesPerOuterBlock; // see C4.2(c)
        // handling corner case for plaintext.length == 0
        if (numPayloadBlocks == 0)
            numPayloadBlocks = 1;

        int officialBufferSize = numPayloadBlocks*outerBlockSize;
        // allocate computation buffer.
        byte[] buffer = new byte[officialBufferSize+RSA_PREFIX_SIZE]; // actual buffer 2 extra bytes for RSA implementation stability

        prepareBufferWithPadding(buffer, numPayloadBlocks, plaintext, plaintextLength);
        performEncryptionSteps(buffer, officialBufferSize, numPayloadBlocks, senderPrivateKey, sig2SK1, sig2SK2, sig2SK3);

        return buffer;
        }

    /**
     * prepare the buffer contents.
     * The (used) buffer size is to be a multiple both of the "outer" block size (RSA block size)
     * and the "inner" block size (AES block size).
     * In this calculation and padding, the RSA prefix bytes of RSA_PREFIX_SIZE are omitted entirely.
     * C4.2
     *
     * @param buffer           buffer to fill
     * @param numPayloadBlocks the pre-calculated number of "outer" payload blocks
     * @param plaintext        plaintext/payload to be protected
     * @param plaintextLength  the length of the plaintext in the buffer, explicitly
     */
    private void prepareBufferWithPadding(byte[] buffer, final int numPayloadBlocks, final byte[] plaintext, final int plaintextLength)
        {
        int plaintextOffset = 0;
        int offset = 0;
        int numBytes;
        byte[] nonce = new byte[nonceSize];
        rng.nextBytes(nonce); // C4.2(b)

        offset += RSA_PREFIX_SIZE; // the subsequent operations, EXCEPT FOR RSA, ignore the leading bytes.

        // see C4.2(c) for the subsequent lines
        for (int blockCounter = 0; blockCounter < numPayloadBlocks; blockCounter++) // this is the block counter loop.
            {
            // optional safety check
            if (plaintextOffset != blockCounter*numPayloadBytesPerOuterBlock)
                throw new UnsupportedOperationException("offset calculation mismatch");

            // magic ID as block header
            // for use with other algorithms, the length of this has to be adapted to innerBlock size.
            System.arraycopy(MAGIC_ID, 0, buffer, offset, MAGIC_ID.length); // Ck
            offset += MAGIC_ID.length;

            // 8 byte nonce
            System.arraycopy(nonce, 0, buffer, offset, nonceSize); // r
            offset += nonceSize;

            // 4 byte unsigned length, big-endian
            SharedCode.put4ByteUnsignedIntToBuffer(buffer, offset, plaintextLength); //  UINT2BIN (l(κ)/4, |m|)
            offset += 4;

            // 4 byte unsigned block counter ID, big-endian
            SharedCode.put4ByteUnsignedIntToBuffer(buffer, offset, blockCounter); // |m|
            offset += 4;

            // n byte plaintext -
            if (plaintextOffset+numPayloadBytesPerOuterBlock < plaintextLength) //
                {
                numBytes = numPayloadBytesPerOuterBlock; // full use of available space
                }
            else
                {
                numBytes = plaintextLength-plaintextOffset; // remainder use.
                // optional: fill remaining bytes explicitly with 0 or randomness here. by default in java, it's 0.
                }
            System.arraycopy(plaintext, plaintextOffset, buffer, offset, numBytes);
            plaintextOffset += numBytes;
            offset += numBytes;
            }
        // buffer preparation done.
        return;
        }

    /**
     * sig 1, AES,AES, invert order, AES, RSA.
     * <p>
     * optimized procedure:
     * -- AES performed in one full go, so it's 3 ephemeral AES keys only.
     * -- RSA performed once only, on last RSA-sized block.
     * -- no OOB byte transport necessary.
     *
     * @param buffer input to process, and return result in.
     *               In-place implementations possible, depending on crypto library.
     */
    private void performEncryptionSteps(byte[] buffer, int officialBufferSize, int numPayloadBlocks, PrivateKey ourPrivateKey, Key sk1, Key sk2, Key sk3)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            ShortBufferException, InvalidAlgorithmParameterException
        {
        int sBlockSize = symmetricCipher.getBlockSize();

        // steps 1-4 implement C4.2(e)
        // 1. perform AES-CBC encryption with SK1,IV1 over the *entire* data blocks, "SKE CBC"
        symmetricCipher.init(Cipher.ENCRYPT_MODE, sk1, constantSK1IV, rng);
        int step2 = symmetricCipher.doFinal(buffer, RSA_PREFIX_SIZE, officialBufferSize, buffer, RSA_PREFIX_SIZE); // supposed to be copy-safe
        assert (step2 == officialBufferSize);

        // 2. perform AES-CBC encryption with SK2,IV2 over the *entire* data blocks. "SKE CBC"
        symmetricCipher.init(Cipher.ENCRYPT_MODE, sk2, constantSK2IV, rng);
        int step3 = symmetricCipher.doFinal(buffer, RSA_PREFIX_SIZE, officialBufferSize, buffer, RSA_PREFIX_SIZE); // supposed to be copy-safe
        assert (step3 == officialBufferSize);

        // 3. revert order of AES blocks
        // reverse buffer in sBlockSize chunks.
        reverseBuffer(buffer, RSA_PREFIX_SIZE, officialBufferSize, sBlockSize);

        // 4. perform AES-CBC encryption with SK3,IV3 over the *entire* data blocks
        symmetricCipher.init(Cipher.ENCRYPT_MODE, sk3, constantSK3IV, rng);
        int step4 = symmetricCipher.doFinal(buffer, RSA_PREFIX_SIZE, officialBufferSize, buffer, RSA_PREFIX_SIZE); // supposed to be copy-safe
        assert (step4 == officialBufferSize);



        // 5. perform RSA once over the first RSA-sized block, with a special twist
        // setting two fixed starting bytes. C4.2(f) and (g)
        buffer[0] = 0x3e; // MSB must be 0. The entire byte, though, must not be 0.
        buffer[1] = 0x7a; // safety for some cases

        // C4.4(a) - perform RSA
        RSAPrivateKey rsaPrivKey = (RSAPrivateKey) ourPrivateKey; // cast checks for correct key type for the algorithms
        assert (rsaPrivKey.getModulus().bitLength() == asymmetricEncryptionSpec.getKeySizeInBit()); // must match expected size
        asymmetricCipher.init(Cipher.ENCRYPT_MODE, rsaPrivKey);
        // CAVEAT: it's important that the full 256 byte input and output are RSA-encrypted in place!
        // if the library implementation refuses to accept 256 bytes of input and takes only 254 or 255,
        // omit the first one or two bytes accordingly by adjusting the offset.
        // The constants provided here are not tested later, intentionally, to allow for compatibility in such cases.
        // perform in-place encryption of 256 bytes starting from offset 0 in the buffer
        asymmetricCipher.doFinal(buffer, 0, 256, buffer, 0); // in-place from the very first byte

        // C4.4(b)
        // result returned in-place = (c'1, c'2, k)
        return;
        }


    /**
     * decrypt and validate before returning plaintext
     *
     * @param ciphertext the encrypted data to be processed
     * @param rsaPubKey  the public key to be used for decryption
     * @param sk1        the ephemeral symmetric key #1 for decryption
     * @param sk2        the ephemeral symmetric key #2 for decryption
     * @param sk3        the ephemeral symmetric key #3 for decryption
     * @return decrypted and validated data. Returned only if validation is successful.
     *
     * RSA exceptions map to C4.6(a) and C4.6(d)
     *
     * @throws BadPaddingException                the intentional one, with which we indicate an integrity violation
     * @throws DataLengthException                when the RSA fails, on flipping bits in the first byte.
     * @throws InvalidKeyException                key parameter found invalid
     * @throws InvalidAlgorithmParameterException indicates implementation or parameter error
     * @throws ShortBufferException               indicates implementation or parameter error
     * @throws IllegalBlockSizeException          indicates implementation or parameter error
     */
    @NonNull
    public byte[] performDecryptionAndValidation(final byte[] ciphertext, final PublicKey rsaPubKey, final Key sk1, final Key sk2, final Key sk3)
            throws BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, DataLengthException
        {
        // guard clauses
        assert (((RSAPublicKey) rsaPubKey).getModulus().bitLength() == asymmetricEncryptionSpec.getKeySizeInBit()); // must match expected size
        // implicit size limit check: ciphertext may not be longer than 2^31-1

        // step 0: prepare sizes and offsets
        byte[] buffer = ciphertext;
        int inputSize = buffer.length;

        if (inputSize%innerBlockSize != RSA_PREFIX_SIZE)
            throw new BadPaddingException(); // ciphertext length doesn't add up algorithm

        int numSymmetricalBlocks = (inputSize-RSA_PREFIX_SIZE)/innerBlockSize;
        int officialBufferSize = numSymmetricalBlocks*innerBlockSize;

        if ((officialBufferSize%outerBlockSize) != 0)
            throw new BadPaddingException(); // ciphertext length doesn't add up algorithm

        // numPayloadBytesPerOuterBlock = outerBlockSize-HEADER_SIZE; -- performed in constructor upon knowledge of key size
        // calculate number of blocks, divide and round up.
        int numBlocks = (officialBufferSize+outerBlockSize-1)/outerBlockSize;

        if ((officialBufferSize%outerBlockSize) != 0)
            throw new BadPaddingException(); // ciphertext length doesn't add up with key size)

        performDecryptionSteps(rsaPubKey, sk1, sk2, sk3, buffer, officialBufferSize, innerBlockSize);
        return verify_after_decryption(numBlocks, buffer, inputSize);
        }

    // recovery
    private void performDecryptionSteps(final PublicKey rsaPubKey, final Key sk1, final Key sk2, final Key sk3, byte[] buffer, final int officialBufferSize, final int sBlockSize)
            throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
        {
        // step 1: apply RSA decryption at the "last block". detect exceptions.
        // perform in-place decryption of 256 bytes starting from fixed offset 0 in the buffer
        // C4.6(c)
        asymmetricCipher.init(Cipher.DECRYPT_MODE, rsaPubKey, rng);
        asymmetricCipher.doFinal(buffer, 0, outerBlockSize, buffer, 0);
        // reminder: the other operations start at bufferStartOffset
        // RSA_PREFIX_SIZE offset stands in for C4.3(a)

        // subsequent steps 2-4  represent C4.3(b)
        // step 2: apply AES decryption with sk3, iv3
        symmetricCipher.init(Cipher.DECRYPT_MODE, sk3, constantSK3IV, rng);
        int step4 = symmetricCipher.doFinal(buffer, RSA_PREFIX_SIZE, officialBufferSize, buffer, RSA_PREFIX_SIZE); // supposed to be copy-safe
        assert (step4 == officialBufferSize);

        // step 3: revert AES blocks in entire buffer
        reverseBuffer(buffer, RSA_PREFIX_SIZE, officialBufferSize, sBlockSize);

        // step 4: apply AES decryption with sk2, iv2
        symmetricCipher.init(Cipher.DECRYPT_MODE, sk2, constantSK2IV, rng);
        int step3 = symmetricCipher.doFinal(buffer, RSA_PREFIX_SIZE, officialBufferSize, buffer, RSA_PREFIX_SIZE); // supposed to be copy-safe
        assert (step3 == officialBufferSize);

        // step 4: apply AES decryption with sk1, iv1
        symmetricCipher.init(Cipher.DECRYPT_MODE, sk1, constantSK1IV, rng);
        int step2 = symmetricCipher.doFinal(buffer, RSA_PREFIX_SIZE, officialBufferSize, buffer, RSA_PREFIX_SIZE); // supposed to be copy-safe
        assert (step2 == officialBufferSize);
        return;
        }

    // Vrf
    private byte[] verify_after_decryption(int numBlocks, byte[] buffer, int inputSize)
            throws BadPaddingException
        {
        // --- place in separate function
        // sig_2_validation
        // step 5: validation
        // -- the constant value ("MagicID") must be as expected in all places it is
        // -- the length value must be the same, and valid within possible range
        // -- the counter values must be in sequence and as expected
        int offset = RSA_PREFIX_SIZE; // source buffer offset
        int plaintextOffset = 0; // destination buffer offset.
        int tmp;

        int plaintextLength = -1;
        int sequenceID = 0;
        byte[] plaintext = null; // C4.3(f)
        byte[] nonce = null;
        // process all blocks forward, instead of looping multiple times.
        for (int i = 0; i < numBlocks; i++)
            {
            // 1. check expected constant, C4.3(g)i
            if (SharedCode.compareBytes(buffer, offset, MAGIC_ID, 0, MAGIC_ID.length) == false)
                throw new BadPaddingException();  // inconsistency in fixed protective data
            offset += MAGIC_ID.length;

            // 2. test nonce.
            if (nonce == null) // not set yet, see C4.3(c)
                {
                nonce = new byte[nonceSize];
                System.arraycopy(buffer, offset, nonce, 0, nonceSize);
                }
            else // compare against existing, C4.3(g)i
                {
                if (SharedCode.compareBytes(buffer, offset, nonce, 0, nonceSize) == false)
                    throw new BadPaddingException(); // inconsistency in variable protective data
                }
            offset += nonceSize;

            // 3. get and check plaintext length.  see C4.3(d)
            tmp = Math.toIntExact(SharedCode.get4ByteUnsignedIntFromBuffer(buffer, offset));
            offset += 4;
            // check on second block and on; on the first block, we've got to other value to compare with.
            if (plaintextLength < 0) // not set yet
                {
                // plausiblity checks, C4.3(e)
                if (tmp >= inputSize) // could be tighter, but detects a very wide range already
                    throw new BadPaddingException(); // invalid length
                //  would the number of resulting blocks exceed our counter?
                if ((tmp/numPayloadBytesPerOuterBlock) > numBlocks)
                    throw new BadPaddingException(); // more blocks that would make sense
                //... before perusing the value supplied.
                plaintextLength = tmp;
                plaintext = new byte[plaintextLength];
                }
            else // starting value given, check possible. see C4.3(c)
                {
                if (plaintextLength != tmp) // perform check
                    throw new BadPaddingException(); // inconsistency in length parameter
                }

            // 4. get and check sequence ID, C4.3(g)ii - with offset 0
            tmp = Math.toIntExact(SharedCode.get4ByteUnsignedIntFromBuffer(buffer, offset));
            offset += 4;
            // check
            if (tmp != sequenceID)
                throw new BadPaddingException(); // sequence order mismatch
            sequenceID++; // increment expected value for next block.

            // 5. extract the plaintext payload of this block.
            // copy as many payload bytes as the block contains.
            // full numPayloadBytesPerOuterblock if enough bytes are left; all the remaining bytes otherwise.
            // C4.3(g)iii
            tmp = Math.min(plaintextLength-plaintextOffset, numPayloadBytesPerOuterBlock);
            System.arraycopy(buffer, offset, plaintext, plaintextOffset, tmp);
            plaintextOffset += tmp;
            offset += tmp;
            }

        // validate resulting plaintext length against expected plaintext length, C4.3(h)
        if (plaintextOffset != plaintextLength) //
            throw new BadPaddingException();
        // return result
        return plaintext;
        }


    /**
     * revert contents of a byte array for a given block size.
     * helper macro for the algorithm.
     *
     * @param buffer     the buffer in which
     * @param baseOffset offset to start in buffer from; bytes before that are omitted for the reversal.
     * @param length     number of bytes to revert
     * @param sBlockSize block size to revert in.
     */
    public static final void reverseBuffer(byte[] buffer, int baseOffset, int length, int sBlockSize)
        {
        // first, check the block size matches buffer size.
        if (length%sBlockSize != 0)
            throw new IllegalArgumentException("size mismatch: blocks do not fit in without remainder");

        // JDK has no swap primitives, so we have to swap using a temp buffer.
        byte[] tmp = new byte[sBlockSize];
        // now swap blocks, front to end, in place.
        int numBlocksOverall = (length/sBlockSize);
        int numBlocksToSwap = numBlocksOverall/2; // stop in the middle.
        // and if number is uneven, don't swap the middle with itself.
        for (int i = 0; i < numBlocksToSwap; i++)
            {
            int offsetA = baseOffset+i*sBlockSize;
            int offsetB = baseOffset+(numBlocksOverall-1-i)*sBlockSize;
            // swap with temporary buffer.
            System.arraycopy(buffer, offsetA, tmp, 0, sBlockSize);
            System.arraycopy(buffer, offsetB, buffer, offsetA, sBlockSize);
            System.arraycopy(tmp, 0, buffer, offsetB, sBlockSize);
            }
        return;
        }

}
//___EOF___