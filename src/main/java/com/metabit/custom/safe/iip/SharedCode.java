/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.iip;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * "static" code used by multiple classes in the IIP
 * exported from metabitUtils library.
 *
 * @author jwilkes
 * @version $Id: $Id
 */
public class SharedCode
{

    /**
     * <p>calculateNumberOfPayloadBlocks.</p>
     *
     * @param payloadLengthInBytes a int
     * @param payloadBytesPerBlock a int
     * @return a int
     */
    public static int calculateNumberOfPayloadBlocks(final int payloadLengthInBytes, final int payloadBytesPerBlock)
        {
        int paddedDataBytes = payloadLengthInBytes + calculatePadding(payloadLengthInBytes, payloadBytesPerBlock);
        int numberOfDataBlocks = paddedDataBytes/payloadBytesPerBlock;
        return numberOfDataBlocks;
        }

    /**
     * calculate padding required
     * @param number    the current value
     * @param alignment the boundary it is to be aligned with
     * @return the number of additional padding elements that need to be added to be aligned with the alignment value.
     */
    final static int calculatePadding(final int number, final int alignment)
        {
        int diff = (number % alignment);
        return (diff != 0) ? alignment - diff : 0;
        }
    
    /**
     * read a 4-byte unsigned int from a buffer.
     * Precondition: there's at least 4 bytes after offset. No explicit check here, may throw IndexOutOfBoundsException.
     *
     * @param input  byte array to read from
     * @param offset starting offset in byte array
     * @return the unsigned int, placed in a long (since Java doesn't allow unsigned values).
     */
    public static long get4ByteUnsignedIntFromBuffer(byte[] input, int offset)
        {
        ByteBuffer tmpReader = ByteBuffer.wrap(input);
        tmpReader.order(ByteOrder.BIG_ENDIAN);
        int intValue = tmpReader.getInt(offset);
        return Integer.toUnsignedLong(intValue); // wordy version of (intValue & 0x00000000ffffffffL)
        }
    
    /**
     * <p>write8ByteUnsignedLongToBuffer.</p>
     *
     * @param value a {@link java.lang.Long} object
     * @param buffer an array of {@link byte} objects
     */
    public static void write8ByteUnsignedLongToBuffer(final Long value, byte[] buffer)
        {
        assert(buffer.length >= Long.BYTES);
        ByteBuffer wrap = ByteBuffer.wrap(buffer);
        wrap.order(ByteOrder.BIG_ENDIAN);
        wrap.putLong(value);
        return;
        }
    
    /**
     * copy from metabit library
     * byte array compare.
     * NB: no size checks are performed here.
     * For whatever reason, Java System has an arrayCopy, but no arrayCompare.
     *
     * @param sourceA first array of bytes for comparison
     * @param offsetInA offset where to start in the first byte array
     * @param sourceB second array of bytes for comparison
     * @param offsetInB offset where to start in the second byte array
     * @param maxBytesToCompare number of bytes to compare.
     * @return true if all bytes were equal.
     */
    protected static boolean compareBytes(byte[] sourceA, int offsetInA, byte[] sourceB, int offsetInB, int maxBytesToCompare)
        {
        for (int i=0; i<maxBytesToCompare; i++)
            {
            if (sourceA[offsetInA+i] != sourceB[offsetInB+i])
                return false;
            }
        return true;
        }

}
//___EOF___
