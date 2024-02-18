/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 licence.
 */
package com.metabit.custom.safe.iip2;

import com.metabit.custom.safe.safeseal.impl.CryptoSettingsStruct;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SharedCode
{

    /**
     * copy from metabit library
     * byte array compare.
     * NB: no size checks are performed here.
     * For whatever reason, Java System has an arrayCopy, but no arrayCompare.
     *
     * @param sourceA           first array of bytes for comparison
     * @param offsetInA         offset where to start in the first byte array
     * @param sourceB           second array of bytes for comparison
     * @param offsetInB         offset where to start in the second byte array
     * @param maxBytesToCompare number of bytes to compare.
     * @return true if all bytes were equal.
     */
    protected static boolean compareBytes(byte[] sourceA, int offsetInA, byte[] sourceB, int offsetInB, int maxBytesToCompare)
        {
        for (int i = 0; i < maxBytesToCompare; i++)
            {
            if (sourceA[offsetInA+i] != sourceB[offsetInB+i])
                return false;
            }
        return true;
        }

    static int getRSAPrivateKeyLengthInBits(String description)
        {
        Pattern keyLengthFromDescription = Pattern.compile(".+RSA private CRT key,\\s+(\\d{4})\\sbits(?m:$)");
        Matcher matcher = keyLengthFromDescription.matcher(description);
        if (matcher.find() == false)
            throw new UnsupportedOperationException("could not determine key size");
        int privateKeyLength = Integer.valueOf(matcher.group(1));
        return privateKeyLength;
        }

    public void checks(final CryptoSettingsStruct css)
        {
        // some checks.
        int encKeySize = css.getEncryptionKeySize()/8;
        int sig1KeySize = css.getSig1KeySize()/8;
        if (encKeySize%sig1KeySize != 0) throw new IllegalArgumentException("key sizes mismatch");
        int numRawBlocks = encKeySize/sig1KeySize;
        if (numRawBlocks < 3) throw new IllegalArgumentException("key size relation error");
        return;
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
     * read a 4-byte unsigned int from a buffer.
     * Precondition: there's at least 4 bytes after offset. No explicit check here, may throw IndexOutOfBoundsException.
     *
     * @param input  byte array to read from
     * @param offset starting offset in byte array
     * @param value  the
     */
    public static void put4ByteUnsignedIntToBuffer(byte[] input, int offset, int value)
        {
        ByteBuffer tmpWriter = ByteBuffer.wrap(input);
        tmpWriter.order(ByteOrder.BIG_ENDIAN);
        tmpWriter.putInt(offset, value); //@TODO check this doesn't inflict any signedness.
        }


    /**
     * get "outer" encryption block size, asymmetric cryptography
     *
     * @param css crypto settings specifying the algorithms
     * @return size in byte
     */
    public static int outerBlockSize(final CryptoSettingsStruct css)
        { return (css.getEncryptionKeySize()/8); }

    /**
     * get "inner" encryption block size, symmetric cryptography
     *
     * @param css crypto settings specifying the algorithms
     * @return size in byte
     */
    public static int innerBlockSize(final CryptoSettingsStruct css)
        { return (css.getSig1KeySize()/8); }
}
