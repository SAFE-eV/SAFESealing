/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.iip.shared;

/**
 * <p>ByteIntegerConversion class.</p>
 *
 * extracted from metabit utils library.
 * @author jwilkes
 * @version $Id: $Id
 */
public class ByteIntegerConversion
{


    /**
     * <p>readBigEndianIntegerFromByteArray.</p>
     *
     * @param input an array of {@link byte} objects
     * @param offset a int
     * @param sizeInBytes a int
     * @return a long
     */
    public static long readBigEndianIntegerFromByteArray(final byte[] input, int offset, int sizeInBytes)
        {
        assert (sizeInBytes <= 8); // and 8 is pushing it! watch out for signedness issues with Java
        long tmp = 0;
        while (sizeInBytes > 0)
            {
            tmp <<= 8;
            tmp |= ((int) input[offset++]) & 0xFF;
            sizeInBytes--;
            }
        return tmp;
        }


    /**
     * <p>writeBigEndianIntegerToByteArray.</p>
     *
     * @param value the integer value to write
     * @param output an array of {@link byte} objects
     * @param startOffset starting offset in the buffer
     * @param sizeInBytes number of bytes available/to write
     */
    public static void writeBigEndianIntegerToByteArray(long value, byte[] output, final int startOffset, int sizeInBytes)
        {
        int pos = startOffset + sizeInBytes - 1; // start with position of the last byte.
        if (pos > output.length)
            throw new IndexOutOfBoundsException();
        while (sizeInBytes > 0)
            {
            output[pos--] = (byte) (value & 0xFF);
            value >>= 8;
            sizeInBytes--;
            }
        return;
        }

}
