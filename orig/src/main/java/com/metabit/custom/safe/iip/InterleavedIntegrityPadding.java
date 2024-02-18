/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.iip;

import javax.crypto.BadPaddingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;

import static com.metabit.custom.safe.iip.SharedCode.*;

/**
 * core logic for the Integrity Padding with Nonce process:
 * apply / verify the padding.
 * <p>
 * implementation limitations:
 * - java.lang.Integer.MAX_SIZE = 2 GB-1 maximum ciphertext length;
 * - accordingly, the plaintext must be even shorter.
 * - minimum cipherBlockSize is 9, but 16 is the lowest realistic value
 *
 * @author jwilkes
 * @version $Id: $Id
 */
public final class InterleavedIntegrityPadding
{


    /**
     * constructor.
     *
     * @param cipherBlockSize required parameter: size of the cipher blocks, in byte.
     *                        common sizes like 128/192/256 bit (16/25/32 byte) are supported.
     *                        shorter blocks like 8 byte are not supported by this implementation,
     *                        though possible in theory (shortening nonce and payload length size)
     */
    public InterleavedIntegrityPadding(int cipherBlockSize)
        {
        if (cipherBlockSize<NONCE_SIZE+PAYLOAD_LENGTH_SIZE+1) // we need at least this number of bytes.
            throw new IllegalArgumentException("cipher block size too small"); // DES e.g. is not acceptable.
        this.cipherBlockSize = cipherBlockSize;
        this.payloadBytesPerBlock = cipherBlockSize-NONCE_SIZE;
        this.rng = new SecureRandom();
        }

    /**
     * get input, produce output - allocating a temporary buffer for it.
     *
     * @param payload payload data to perform integrity padding on
     * @return the padded data.
     */
    public byte[] performPaddingWithAllocation(final byte[] payload)
        {
        long bufferSizeRequiredLong = calculateNumberOfBytesOverall(payload.length, this.cipherBlockSize);
        if (bufferSizeRequiredLong>Integer.MAX_VALUE)
            throw new IllegalArgumentException("payload too large, maximum size in byte is "+Integer.MAX_VALUE);
        int bufferSizeRequired = Math.toIntExact(bufferSizeRequiredLong);
        byte[] buffer = new byte[bufferSizeRequired];
        performPaddingInPlace(payload, buffer);
        return buffer;
        }

    /**
     * core IIP function: perform the Integrity Padding.
     *
     * @param input        input data for the padding
     * @param outputBuffer buffer to place padded data into. Must be allocated to the correct size!
     * @return number of bytes used in the buffer. For a correctly allocated buffer, this will be equal to the buffer size.
     */
    int performPaddingInPlace(final byte[] input, byte[] outputBuffer)
        {
        // check input parameters
        assert (input!=null);
        assert (outputBuffer!=null);
        // prepare the protection nonce
        byte[] nonce = new byte[NONCE_SIZE];
        rng.nextBytes(nonce);
        long nonceWithCounter = get4ByteUnsignedIntFromBuffer(nonce, 0); // optimisation: instead of modulating the value every time on the nonce value.

        // prepare the buffer
        ByteBuffer bb = ByteBuffer.wrap(outputBuffer);
        bb.order(ByteOrder.BIG_ENDIAN); // network byte order defined.
        if (bb.hasArray()==false)
            throw new UnsupportedOperationException("something's really wrong with the ByteBuffer in this JRE");

        // heading ("header") block
        // write ID, shortened if need be.
        int idSizeUsed = calculateIDsizeUsed();
        bb.put(MAGIC_ID_VERSION_1_0, 0, idSizeUsed);
        // add R0 padding.
        int numHeaderPaddingBytes = cipherBlockSize-(idSizeUsed+NONCE_SIZE+PAYLOAD_LENGTH_SIZE);
        while (numHeaderPaddingBytes>0)
            {
            bb.put((byte) rng.nextInt(256)); // add random byte
            numHeaderPaddingBytes--;
            }
        // we can't use padToBlockSizeWithRandom here since we pad R0 in the *middle* of the header block.

        // write the nonce
        bb.put(nonce); // always written at offset cipherBlockSize - (NONCE_SIZE + PAYLOAD_LENGTH_SIZE)

        // write the length of the payload to be reconstructed at recipient side.
        bb.putInt(input.length); // always written at offset cipherBlockSize - PAYLOAD_LENGTH_SIZE
        assert (bb.position()==cipherBlockSize); // implementation check: header block exactly complete?
        // header block complete.

        // now loop through input data and place it to the buffer
        int offset;
        for (offset = 0; offset<input.length; offset += payloadBytesPerBlock)
            {
            // pre-increment (not post)
            nonceWithCounter++;
            // java.lang.Math.toIntExact would fail here at wraparound. We have to perform this cast ourselves:
            bb.putInt((int) (nonceWithCounter&0x0FFFFFFFFL)); // place 4 byte integer counter CTR first.
            // wenn wir dem ende des blocks näher kommen...
            int remainder = input.length-offset;
            bb.put(input, offset, (remainder>payloadBytesPerBlock) ? payloadBytesPerBlock : remainder); // min(remainder,payloadBytesPerBlock)
            }

        // if last block needs padding, apply it here
        padToBlockSizeWithRandom(bb);

        // check if remainder != 0
        if (input.length % payloadBytesPerBlock == 0) // perfect match means trailing block
            {
            // append trailing block; only necessary if the r1 was empty
            nonceWithCounter++;
            //@CHECK the java Math.toIntExact() function on signedness. we want an unsigned wrap-around, that's why we use long and Math.toIntExact().
            bb.putInt((int) (nonceWithCounter&0x0FFFFFFFFL)); // place 4 byte integer counter CTR.
            padToBlockSizeWithRandom(bb); // fill up
            }

        // with clean block input, this should equal block length
        return bb.position(); // number of bytes used
        }

    /**
     * core IIP function: validate the Integrity Padding, and extract payload data.
     *
     * @param paddedData data to perform validation on.
     * @return extracted payload data.
     * @throws javax.crypto.BadPaddingException      in all cases where the validation fails.
     * @throws java.lang.IllegalArgumentException if the buffer supplied is of incorrect size. added to aid implementation checks.
     *                                  no security relevance since an attacker would know the cipher block size anyhow.
     */
    public byte[] checkAndExtract(byte[] paddedData) throws BadPaddingException
        {
        // guard clause
        if (paddedData.length%cipherBlockSize!=0)
            throw new IllegalArgumentException("buffer size invalid");
        // preparition of local variables
        byte[] id = new byte[MAGIC_ID_LENGTH];
        byte[] nonce = new byte[NONCE_SIZE];
        byte[] lengthBuffer = new byte[PAYLOAD_LENGTH_SIZE];
        byte[] payloadBuffer = null;
        int idLengthExpected = calculateIDsizeUsed();
        int numHeaderPaddingBytes = cipherBlockSize-(idLengthExpected+NONCE_SIZE+PAYLOAD_LENGTH_SIZE);
        boolean success = true;

        ByteBuffer bb = ByteBuffer.wrap(paddedData);
        bb.order(ByteOrder.BIG_ENDIAN);
        try
            {
            // 1. start reading
            bb.get(id, 0, idLengthExpected);
            while (numHeaderPaddingBytes>0)
                {
                bb.get(); // skip
                numHeaderPaddingBytes--;
                }
            bb.get(nonce);
            bb.get(lengthBuffer);
            int payloadLength = Math.toIntExact(get4ByteUnsignedIntFromBuffer(lengthBuffer, 0)); // implementation limit 2GB

            // 2. check ID
            if (compareBytes(id, 0, MAGIC_ID_VERSION_1_0, 0, idLengthExpected)==false)
                success = false;
            // early exit possible.

            // 3. convert and check length
            // first rough check
            if (payloadLength>=paddedData.length)
                throw new BadPaddingException(); // in this case, we have to quit early, since we cannot predict the number of subsequent blocks correctly
            int expectedPayloadBlocks = calculateNumberOfPayloadBlocks(payloadLength, payloadBytesPerBlock);
            //@IMPROVEMENT different calculation allowing us to delay the exit, eg. from overall length and cipherBlockSize

            // 3. get nonce counter ready
            long nonceCounter = get4ByteUnsignedIntFromBuffer(nonce, 0);

            // 4. prepare output buffer. -- for supplied buffers, there is a requirement of minimum size to be checked.
            payloadBuffer = new byte[payloadLength];

            // 5. loop through all expected blocks
            int payloadOffset = 0;
            for (int i = 0; i<expectedPayloadBlocks; i++)
                {
                nonceCounter++;
                long givenCounterValue = Integer.toUnsignedLong(bb.getInt());
                if (givenCounterValue!=nonceCounter)
                    success = false; // foil timing attacks here by not exiting right away.
                // copy payload data over
                int remainder = payloadLength-payloadOffset;
                bb.get(payloadBuffer, payloadOffset, (remainder>payloadBytesPerBlock) ? payloadBytesPerBlock : remainder);
                payloadOffset += payloadBytesPerBlock;
                }

            // check whether to expect a trailing block or not

            if (payloadLength % payloadBytesPerBlock == 0) // perfect match means trailing block
                {
                // 6. skip optional padding to next block start
                skipToBlockSize(bb);
                // 7. check trailing nonce copy to match to the heading one.
                nonceCounter++;
                long givenCounterValue = Integer.toUnsignedLong(bb.getInt());
                if (givenCounterValue!=nonceCounter)
                    success = false; // foil timing attacks here by not exiting right away.

                // 8. omit/ignore trailing random data after that.
                skipToBlockSize(bb); // not needed for validation, just to access the bytes in memory
                }

            // plausibility check whether we've accurately reached the end.
            if (payloadOffset<payloadLength)
                success = false;
            // plausibility check whether the remaining # of bytes is less than blocksize. otherwise, something's off.
            if (bb.hasArray()) // arrayOffset is available only if this is given.
                {
                if (bb.arrayOffset()%cipherBlockSize>payloadBytesPerBlock)
                    success = false;
                }
            }
        catch (ArithmeticException ex)
            {
            success = false; //integer overflow from Math.toIntExact if one of those values is corrupted
            }
        // 8. result: OK or failure.
        if (success!=true)
            throw new BadPaddingException();
        return payloadBuffer;
        }

//------------------------------------------------------------------------------------------------------------------
// support functions

    /**
     * support function: pad to cipher block size, filling with random data.
     *
     * @param bb handle for byte array, with numerical position cursor (offset)
     */
    private void padToBlockSizeWithRandom(ByteBuffer bb)
        {
        // fill up to block size with random data.
        int currentOffset=bb.position();
        int currentDiff=calculatePadding(currentOffset, cipherBlockSize);
        while (currentDiff!=0) // if not at block boundary, fill with random data.
            {
            bb.put((byte) rng.nextInt(256));
            currentDiff--;
            }
        return;
        }

    /**
     * support function: in a byte buffer, skip ahead to the next block boundary.
     * @param bb ByteBuffer for which to do this.
     */
    private void skipToBlockSize(ByteBuffer bb)
        {
        int currentOffset=bb.position();
        int currentDiff=calculatePadding(currentOffset, cipherBlockSize);
        while (currentDiff!=0) // if not at block boundary, fill with random data.
            {
            bb.get();
            currentDiff--;
            }
        return;
        }

    /**
     * specific support function: calculate number of bytes from the ID value to be used in given circumstances.
     *
     * @return number of ID bytes to be used.
     */
    private int calculateIDsizeUsed()
        {
        int headerPad=cipherBlockSize-(MAGIC_ID_LENGTH+NONCE_SIZE+PAYLOAD_LENGTH_SIZE);
        if (headerPad==0) // a perfect match would leave no space for the R0, so we shorten the ID by 1.
            {headerPad=-1;}
        if (headerPad<0)
            {return MAGIC_ID_LENGTH+headerPad;} // shortened
        else
            {return MAGIC_ID_LENGTH;} // full length
        }

    /**
     * calculate the buffer size.
     *
     * @param payloadLengthInBytes how many bytes of payload data are to be protected and encrypted
     * @param cipherBlockSize      how many bytes fit in a crypto algorithm block
     * @return the required buffer size, in byte
     */
    public static long calculateNumberOfBytesOverall(final int payloadLengthInBytes, final int cipherBlockSize)
        {
        int payloadBytesPerBlock=cipherBlockSize-NONCE_SIZE;
        return (long)cipherBlockSize * (long)calculateNumberOfBlocksOverall(payloadLengthInBytes, payloadBytesPerBlock);
        }

    /* this implementation prefers legibility to efficiency. compilers will be able to optimise this nicely */
    private static int calculateNumberOfBlocksOverall(final int payloadLengthInBytes, final int payloadBytesPerBlock)
        {
        int numberOfDataBlocks = calculateNumberOfPayloadBlocks(payloadLengthInBytes + NONCE_SIZE, payloadBytesPerBlock);
        int numberOfBlocks = 1 + numberOfDataBlocks; // header block + data blocks
        return numberOfBlocks;
        }

    // --- class constants ---
    final static byte[] MAGIC_ID_VERSION_1_0 = {0x3E, 0x7A, (byte) 0xB1, 0x70, 0x5A, (byte) 0xFE, (byte) 0xE4, 0x10}; // 0x3E7AB1705AFEE410L
    private static final int MAGIC_ID_LENGTH = 8;
    public final static int NONCE_SIZE = 4; // 4 byte.
    final static int PAYLOAD_LENGTH_SIZE = 4; // 4 byte.
    // --- class member variables ---
    private final SecureRandom rng;
    private final int payloadBytesPerBlock;
    private final int cipherBlockSize;
}
//___EOF___
