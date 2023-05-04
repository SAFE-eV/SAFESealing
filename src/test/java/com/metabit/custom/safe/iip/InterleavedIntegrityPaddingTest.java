package com.metabit.custom.safe.iip;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.metabit.support.format.HexDump;

import javax.crypto.BadPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;

import static com.metabit.custom.safe.iip.InterleavedIntegrityPadding.NONCE_SIZE;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class InterleavedIntegrityPaddingTest
{
    public static final String TEST_DATA_STRING = "S.A.F.E. - Software Alliance for E-mobility";
    public static final int CIPHER_BLOCK_SIZE = 16;
    public static final int PAYLOAD_BYTES_PER_BLOCK = 12;
    private SecureRandom rng;

    @BeforeEach
    void setUp()
        {
        Security.addProvider(new BouncyCastleProvider());
        rng = new SecureRandom();
        }

    @Test
    void calculateNumberOfBytesOverall()
        {
        // just a minimal test with fixed data
        int result;

        for (int i = 1; i < 8192; i++) // 8192 is just to limit the runtime.
            {
            result = Math.toIntExact(InterleavedIntegrityPadding.calculateNumberOfBytesOverall(i, CIPHER_BLOCK_SIZE));

            int expectedBytes = 0;
            expectedBytes += CIPHER_BLOCK_SIZE; // header is a full block
            int dataBlockBytes = i + NONCE_SIZE;
            int numDataBlocks = dataBlockBytes / PAYLOAD_BYTES_PER_BLOCK; // java int division always rounds down.
            if (dataBlockBytes % PAYLOAD_BYTES_PER_BLOCK != 0)
                numDataBlocks += 1; // so, one more.
            expectedBytes += numDataBlocks * CIPHER_BLOCK_SIZE; // taking up full blocks

            assertEquals(expectedBytes,result);
            }
        return;
        }
    @Test
    void performPaddingWithAllocationSimpleTest() throws BadPaddingException
        {
        InterleavedIntegrityPadding instance = new InterleavedIntegrityPadding(CIPHER_BLOCK_SIZE);
        byte[] input = TEST_DATA_STRING.getBytes(StandardCharsets.UTF_8);
        System.out.println(HexDump.bytesToHexString(input, " ", CIPHER_BLOCK_SIZE));
        byte[] padded = instance.performPaddingWithAllocation(input);
        System.out.println(HexDump.bytesToHexString(padded, " ", CIPHER_BLOCK_SIZE));
        byte[] extracted = instance.checkAndExtract(padded);
        assertArrayEquals(input, extracted);
        }

    @Test
    void performFullTestWithRandomData() throws BadPaddingException
        {
        InterleavedIntegrityPadding instance = new InterleavedIntegrityPadding(CIPHER_BLOCK_SIZE);

        for (int i = 1; i < 8192; i++) // 8192 is just to limit the runtime.
            {
            byte[] input = new byte[i];
            rng.nextBytes(input); // random input data
            byte[] padded = instance.performPaddingWithAllocation(input);
            byte[] extracted = instance.checkAndExtract(padded);
            assertArrayEquals(input, extracted);
            }
        return;
        }


    // not ready yet for RSA blocksizes.

    @Test
    void performFullTestWithRandomDataAndRSABlocksizes() throws BadPaddingException
        {
        int[] blockSizes = new int[]{128, 256, 512}; // for RSA keys 1024, 2049, 4096 bit respectively
        for (int blocksize : blockSizes)
            {
            InterleavedIntegrityPadding instance = new InterleavedIntegrityPadding(blocksize);

            for (int i = 1; i < 8192; i++) // 8192 is just to limit the runtime.
                {
                byte[] input = new byte[i];
                rng.nextBytes(input); // random input data
                byte[] padded = instance.performPaddingWithAllocation(input);
                byte[] extracted = instance.checkAndExtract(padded);
                assertArrayEquals(input, extracted);
                }
            }
        return;
        }

    @Test
    void testJavaIntegerWraparound()
        {
        //check the java Math.toIntExact() function on signedness.
        // we want an unsigned wrap-around, that's why we use long and Math.toIntExact().
        final long startValue = ((long) Integer.MAX_VALUE) - 2;
        final long endValue = ((long) Integer.MAX_VALUE) + 2;

        for (long testValue = startValue; testValue <= endValue; testValue++)
            {
            // final int convertedA = Math.toIntExact(testValue);
            final int convertedB = (int) (testValue&0x0FFFFFFFFL);
            System.out.println(convertedB);
            }
        return;
        }

}
//___EOF___