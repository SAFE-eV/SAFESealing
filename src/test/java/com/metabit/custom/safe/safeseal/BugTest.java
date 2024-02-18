package com.metabit.custom.safe.safeseal;

import com.metabit.custom.safe.iip.InterleavedIntegrityPadding_V1_0;
import com.metabit.custom.safe.iip.RSATestKeyStorage;
import com.metabit.custom.safe.iip.shared.AlgorithmSpec;
import com.metabit.custom.safe.iip.shared.AlgorithmSpecCollection;
import com.metabit.custom.safe.iip.shared.CryptoFactory;
import com.metabit.custom.safe.safeseal.impl.CryptoFactoryImpl;
import com.metabit.platform.java.supplymissing.ByteArrayOperations;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.DataLengthException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.metabit.library.misc.util.stats.SimpleIntegerStatsCounter;
import org.metabit.support.format.HexDump;

import javax.crypto.*;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * this test performs specific "test attacks", artificially constructing cases where a possible bug is triggered:
 * a trailing zero appears/differs.
 * This may be without practical impact for the SAFESealing use case, since the plaintext, JSON/XML formatted,
 * do not contain zero bytes; if compression is activated (which it is by default), there is a low chance of this to
 * happen in practical use.
 * However, any such flaw needs to be investigated, and if proven, remedied.
 * <p>
 * NB: This bug happens with plain RSA.
 */
@Slf4j
@EnabledIfEnvironmentVariable(named = "statistics", matches = "true") // run only when specifically activated, not on maven test phase during regular builds
class BugTest
{
public static  String       TEST_DATA_HEX_DUMP = "3E 7A B1 70 5A FE E4 10 D8 19 03 FF D4 65 9B C7 E4 EF F6 98 37 2E 09 51 AB 08 40 38 A2 3E D0 4F\n"+"        0A B5 C3 73 D3 4A 40 D1 91 2E 23 29 90 79 F4 D9 B5 00 51 61 5B DA E2 2D C3 65 F4 F5 04 70 93 F5\n"+"        51 53 AC 82 33 EB 5D 73 55 DC B5 8D 11 6B 35 F4 22 8A 41 D9 A1 6C A0 5F 5C E5 0C DC 01 21 A6 09\n"+"        53 5F 44 3E 24 9E 5F C7 50 03 56 73 5C A7 C4 E1 F4 07 6F 63 49 92 E9 DE 12 EF F2 45 6D 42 37 9E\n"+"        09 C0 DA A1 AC 21 2C A7 41 DC B6 90 52 21 C2 7A 05 7C 8B B3 4D 07 CA F7 3D D6 8C E3 50 C6 2F 6E\n"+"        6B C4 D8 B7 C6 B6 78 F7 E6 F6 68 C0 2A A9 31 5C A2 01 33 07 9B 5C 42 23 D0 90 02 BE DE F5 DB 02\n"+"        2D F9 40 0E B2 D1 27 F9 5E 17 BD 88 DB 9A 8E 90 83 14 04 07 EC 58 96 F5 A1 89 83 D7 CF 56 68 0F\n"+"        C8 43 18 CA CC DC 92 27 D8 F9 D6 CC 7C 52 6F 68 28 B1 61 CD 03 B2 50 00 9B B5 EA 00 00 00 43 00\n"+"\n"+"        9B B5 EB BB 3A 5B 14 2E 5A 4C 1E 47 11 D4 14 23 BE 2B 2B DA 27 CA 02 6B 85 FE 1C D7 69 C9 70 90\n"+"        54 1E 47 10 CF 40 3E CE BA C4 77 0D 81 A2 60 89 F8 CE 97 EE CE 9B C3 B7 5F 39 11 29 22 0F 59 F7\n"+"        91 F9 04 05 10 93 1D 5E 2D B9 AB 5F FC 50 05 FA 15 47 3B 6C F5 7E 7A 5C 56 52 7B 89 8A 81 6B C9\n"+"        3D 5A 9B E1 B7 95 BF 9B 58 AC 8F F0 F2 BC 6A A2 E5 AD 4B 4A 1D 49 5E 8E BE 52 12 CE 63 47 4A D2\n"+"        6E 03 CD 97 9F 97 E3 03 76 4D 20 CB 60 63 0F 55 EB C1 62 C6 04 FC EC E0 3F 27 C8 BB A6 C8 A3 C3\n"+"        C2 E6 F8 96 44 0E 64 33 B9 F3 92 B8 B6 84 85 FF 7D C4 FB 5A 3F F6 65 55 58 7D E7 65 2B 2E F0 21\n"+"        B2 36 CB 13 85 D8 1E 94 DC CC 91 A8 50 DD 31 20 FF F7 21 54 E7 06 B7 96 1B C2 55 55 6D 1B D7 D2\n"+"        73 E8 B8 66 1C 8D EE AB 52 68 BD 69 92 0E CA F9 92 FD 47 94 37 50 A7 D6 79 C0 CB 5B B6 D1";
private static SecureRandom rng;
// these are the asymmetric key pairs; we consider them in place before the scheme is applied (precondition).

// multiline string available from Java 15
private static CryptoFactory cryptoFactory;

    /*
    lessons learned:
    -- the issue does not arise with every key. Only some keys/key pairs have this effect.
    -- the trailing zero byte happens after encryption, not inside the padding. The padding itself seems to have no effect there.
    -- q: is there special handling required b/o ECB?
     */
    @Test
    void testRSAtrailingZeroIssue()
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException,
            InvalidKeyException, IOException
        {
        Base64.Encoder encoderInstance = Base64.getEncoder();
        AlgorithmSpec algorithmSpec = AlgorithmSpecCollection.RSA2048;

        int counter = 0;

        for (int i=0; i<1000; i++)
            {
            final KeyPair rsaKeyPair = generateRSAKeyPair(algorithmSpec.getKeySizeInBit());
            PrivateKey senderPrivateKey = rsaKeyPair.getPrivate();
            PublicKey senderPublicKey = rsaKeyPair.getPublic();


            int payloadSize = 47;
            // generate test data
            byte[] testPayload = new byte[payloadSize];
            rng.nextBytes(testPayload);

            // perform the IIP padding
            InterleavedIntegrityPadding_V1_0 integrityPaddingInstance = new InterleavedIntegrityPadding_V1_0(algorithmSpec.getUsableBlockSize());
            byte[] padded = integrityPaddingInstance.performPaddingWithAllocation(testPayload);
            // padded[255] = (byte)0x80; // OK. that fixes it. non-zero?
            padded[255] = 0; // Problem provozieren


            // encrypt the test data
            byte[] encrypted = rsa_encrypt_blocks(algorithmSpec, senderPrivateKey, padded);
            // --- "positive": decrypt and verify without having anything changed.
            byte[] decrypted = rsa_decrypt_blocks(algorithmSpec, senderPublicKey, encrypted);
            // this test tells us our encrypt/decrypt functions work.
            // assertArrayEquals(padded, decrypted); //
            if (!ByteArrayOperations.arrayCompare(decrypted, 0, padded, 0, decrypted.length))
                {
                System.err.println("encryption/decryption didn't match");
                //                System.out.println(RSATestKeyStorage.convertRSAKeyToJSON(rsaKeyPair,encoderInstance));
/*
                System.err.println(encrypted.length);
                System.err.println("before:");
                System.err.println(HexDump.bytesToHexString(padded, " ", 32));
                System.err.println("after:");
                System.err.println(HexDump.bytesToHexString(decrypted, " ", 32));
*/
                //@TODO save this key pair for later reuse/tests.
                }
            }
        // OK.
        return;
        }

    @Test
    void performIIPtestsForStandardRSABlocksizes() throws BadPaddingException
        {
        int[] blockSizes = new int[] {128, 256, 512}; // for RSA keys 1024, 2049, 4096 bit respectively
        for (int blocksize : blockSizes)
            {
            InterleavedIntegrityPadding_V1_0 instance = new InterleavedIntegrityPadding_V1_0(blocksize);

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


private static void printResults(PrintStream out, Map<Integer, Integer> encryptedSizesInBits, Map<Integer, SimpleIntegerStatsCounter> hammingDistances, Map<Integer, Integer> detectionHits)
    {
    // System.out.println("bits overall: "+payloadSize*8);
    // MD table header
    out.println("| payload size | minimum | average | maximum | padded size | # of samples which | ");
    out.println("| (in byte)    |  | hamming distance  |      | (in bit)    | passed decryption  | ");
    out.println("| -----------: | ------: | ------: | ------: | ----------: | ----------------:  |");
    hammingDistances.forEach((payloadSizeInBytes, hammingDistanceCounter)->
        {
        out.print(" | ");
        out.print(payloadSizeInBytes);
        out.print(" | ");
        // the hamming distances
        out.print(hammingDistanceCounter.getAllTimeMinimum());
        out.print(" | ");
        out.print(hammingDistanceCounter.getArithmeticMeanAsDouble());
        out.print(" | ");
        out.print(hammingDistanceCounter.getAllTimeMaximum());
        out.print(" | ");

        final Integer encBits = encryptedSizesInBits.get(payloadSizeInBytes);
        out.print(encryptedSizesInBits.get(payloadSizeInBytes)); // how many single-bit-tests we did
        out.print(" | ");
        out.print(hammingDistanceCounter.getNumberOfValuesCounted());
        out.print(" | ");
/*
            // now the detection types
            out.print(detectionHits.get(payloadSizeInBytes)); // how many of these cases the IIP gets to check
            out.print(" | ");
            out.print((double) detectionHits.get(payloadSizeInBytes) / encBits);
            out.print(" | ");
*/
        out.println();
        });
    }



public static KeyPair generateRSAKeyPair(int keySize)
        throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
    {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4));
    return kpg.generateKeyPair();
    }

@BeforeAll
static void globalInit()
    {
    cryptoFactory = new CryptoFactoryImpl();
    rng = new SecureRandom();
    }

public byte[] getTestData()
        throws IOException
    {
    String tmp = new String(Files.readAllBytes(Paths.get("src/main/resources/TEST_CASE_1_HEXDUMP.txt")));
    //@TODO conversion to byte array!
    // check by re-dumping it.

    return tmp.getBytes(StandardCharsets.UTF_8);
    }

/**
 * perform a full test on a test message: change each bit of the wrapped message and check what happens.
 * <p>
 * As opposed to the AttackTest class, which tests at full wrapper level (using sealer/revealer classes),
 * this test has to operate at a lower level. The API-level classes do not give us access to the "failed"
 * decryption data; instead, they throw a BadPaddingException (as they should).
 * <p>
 * For calculating statistics, though, we want to see the degree of divergence.
 */
@Test
void attackTestWithStatistics()
        throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, ShortBufferException,
        BadPaddingException
    {
    AlgorithmSpec algorithmSpec = AlgorithmSpecCollection.RSA2048;
    //    case 4096: spec = AlgorithmSpecCollection.RSA4096; break;

    // -------------------------------------------------------------------------------------------------------------
    // init with calculated average, since we want to know the minimum. otherwise, this will start with ß
    // key: the payload size
    Map<Integer, Integer> encryptedSizesInBits = new HashMap<>();
    Map<Integer, SimpleIntegerStatsCounter> hammingDistances = new HashMap<>();
    Map<Integer, Integer> decryptionHits = new HashMap<>(); // how often the decryption throws an exception, before we can perform our own testing.
    Map<Integer, Integer> detectionHits = new HashMap<>(); // how often the IIP detection gets to find an issue (after decryption allows us to).

    InterleavedIntegrityPadding_V1_0 integrityPaddingInstance = new InterleavedIntegrityPadding_V1_0(algorithmSpec.getUsableBlockSize());

    for (int numKeypairsTested = 1; numKeypairsTested < 10; numKeypairsTested++)
        {
        final KeyPair rsaKeyPair = generateRSAKeyPair(algorithmSpec.getKeySizeInBit());
        PrivateKey senderPrivateKey = rsaKeyPair.getPrivate();
        PublicKey senderPublicKey = rsaKeyPair.getPublic();

        // generate random payload data of different sizes
        for (int payloadSize = 2; payloadSize < 80; payloadSize += 1)
            // int payloadSize = 345;
            {
            testAllBitChanges(payloadSize, algorithmSpec, senderPrivateKey, senderPublicKey, integrityPaddingInstance, 3, encryptedSizesInBits, hammingDistances, decryptionHits, detectionHits);
            } // end of the block-size loop
        }
    // above cannot detect the hamming distance - every deviation causes an BadPaddingException, intentionally.
    printResults(System.out, encryptedSizesInBits, hammingDistances, detectionHits);
    return;
    }

/**
 * for a given size, generate random payload, pad and encrypt; and for each of the encrypted bits, test that changes are detected.
 * // inputs
 *
 * @param payloadSize              payload size to test for
 * @param algorithmSpec            encryption to use
 * @param senderPrivateKey         private key to use
 * @param senderPublicKey          corresponding public key to use
 * @param integrityPaddingInstance IIP instance to use.
 * @param numBitsToChange          how many bits to change. defaults to 1. use higher number for burst errors.
 *                                 // outputs
 * @param encryptedSizesInBits     for the given payload size, put number of encrypted data bits
 * @param hammingDistances         for the given payload size, put statistics about the hamming distances
 * @param decryptionHits           for the given payload, put how many changes were rejected by the decryption
 * @param detectionHits            for the given payload, put how many changes were detected by the IIP padding detection.
 *                                 <p>
 *                                 detectionHits + decryptionHits == encyptedSizesInBits
 * @throws NoSuchPaddingException
 * @throws NoSuchAlgorithmException
 * @throws NoSuchProviderException
 * @throws InvalidKeyException
 * @throws ShortBufferException
 * @throws IllegalBlockSizeException
 * @throws BadPaddingException
 */
private void testAllBitChanges(final int payloadSize, final AlgorithmSpec algorithmSpec, final PrivateKey senderPrivateKey, final PublicKey senderPublicKey, InterleavedIntegrityPadding_V1_0 integrityPaddingInstance, final int numBitsToChange, Map<Integer, Integer> encryptedSizesInBits, Map<Integer, SimpleIntegerStatsCounter> hammingDistances, Map<Integer, Integer> decryptionHits, Map<Integer, Integer> detectionHits)
        throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
    assert (numBitsToChange > 0);
    // init with calculated average, so we can see deviations up and down. Without init, this would default to 0, and we couldn't detect low hamming distances.
    SimpleIntegerStatsCounter hammingDistanceCounter = new SimpleIntegerStatsCounter(payloadSize*8/2);

    // generate test data
    byte[] testPayload = new byte[payloadSize];
    rng.nextBytes(testPayload);

    // perform the IIP padding
    byte[] padded = integrityPaddingInstance.performPaddingWithAllocation(testPayload);

    // encrypt the test data
    byte[] encrypted = rsa_encrypt_blocks(algorithmSpec, senderPrivateKey, padded);

    // note the number of bits we have in the encrypted
    int numBlocks = encrypted.length/algorithmSpec.getCipherBlockSize();
    encryptedSizesInBits.put(payloadSize, encrypted.length*8); // how many bits there are to be affected by potential changes

    // --- "positive": decrypt and verify without having anything changed.
    byte[] decrypted = rsa_decrypt_blocks(algorithmSpec, senderPublicKey, encrypted);
    // this test tells us our encrypt/decrypt functions work.
    // assertArrayEquals(padded, decrypted); //
    if (!ByteArrayOperations.arrayCompare(decrypted, 0, padded, 0, decrypted.length))
        {
        System.err.println("encryption/decryption didn't match");
        System.err.println("before:");
        System.err.println(HexDump.bytesToHexString(padded, " ", 32));
        System.err.println("after:");
        System.err.println(HexDump.bytesToHexString(decrypted, " ", 32));

        assert (false); // fail.
        }

    // --- deviation tests: change single bits. ---
    int len = encrypted.length;
    // now for the manipulation tests. we make copies of the sealed data and flip bits.
    byte[] tampered = new byte[len];
    int bitsInEncryptedForm = len*8;

// System.out.print(bitsInEncryptedForm + " : ");
    int decryptionRejected = 0;
    int detectionDetected = 0;
    // single-bit changes; *each* bit is tested
    for (int bit = 0; bit < bitsInEncryptedForm; bit++)
        {
        System.arraycopy(encrypted, 0, tampered, 0, len); // re-initialise the "tampered" array
        int burstSize = numBitsToChange; // how many bits to change
        if (bit+numBitsToChange >= bitsInEncryptedForm) // limit if we're at the end of the array, to avoid index-out-of-bounds-error
            {
            burstSize = (bitsInEncryptedForm-bit); // may be 0 in rare cases at the very end.
            }
        for (int i = bit; i < bit+burstSize; i++) // for each of those bits
            {
            tampered[i/8] ^= (1<<(i%8)); // flip the single "i-th" bit
            }
        // test detection
        try
            {
            // in many cases, the RSA decryption will already fail with an ArrayIndexOutOfBoundsException
            decrypted = rsa_decrypt_blocks(algorithmSpec, senderPublicKey, tampered);
            // so we do not get to calculate a hamming distance at all for these cases.

            // we expect this decrypted data to be quite different from the expected padded input.
            // JUnit has no assertArrayNotEquals as of now, though.
            // for this specific test, we include the metabit util library anyhow.
            int hammingDistance = ByteArrayOperations.arrayBitDifferenceCounting(padded, 0, decrypted, 0, padded.length);
            Assertions.assertNotEquals(0, hammingDistance); // must never be undetected
            hammingDistanceCounter.put(hammingDistance);
            // now record the hamming distance.
            // we want for: keysize; payload size   to know the *average* hamming distance.
            // to that end, we
            // hammingDistances.put(payloadSize,hammingDistances.getOrDefault(bit, 0)+1));

            // and now test the IIP code whether it detects the changes.
            final byte[] extractedPayload = integrityPaddingInstance.checkAndExtract(decrypted);
            assertArrayEquals(testPayload, extractedPayload);
            // should it ever not detect the change, the test will fail here.
            }
        catch (ArrayIndexOutOfBoundsException|DataLengthException ex)
            {
            decryptionRejected++;
// System.out.print('-');
            } // this is the expected case
        catch (BadPaddingException ex)
            {
            detectionDetected++;
// System.out.print('x');
            } // this is the expected case
        catch (Exception ex) // all the other exceptions should be caught and replaced
            {
            System.err.println("naked exception at flipped bit "+bit+", "+ex);
            ex.printStackTrace();
            }
        } // end the each-bit-loop
// System.out.println();
    hammingDistances.put(payloadSize, hammingDistanceCounter);

    decryptionHits.put(payloadSize, decryptionRejected);
    detectionHits.put(payloadSize, detectionDetected);
    assert (decryptionRejected+detectionDetected == bitsInEncryptedForm);
    }


    private static byte[] rsa_encrypt_blocks(AlgorithmSpec algorithmSpec, PrivateKey senderPrivateKey, byte[] padded)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException
        {
        Cipher cipher = cryptoFactory.getCipherFromCipherSpec(algorithmSpec);
        int usable_blocksize = algorithmSpec.getUsableBlockSize();
        int RSA_blocksize = algorithmSpec.getCipherBlockSize();

        cipher.init(Cipher.ENCRYPT_MODE, senderPrivateKey, rng);
        // rsa will support single blocks only, so we have to split ourselves.
        int inputLength = padded.length;
        int outputLength = (inputLength/usable_blocksize)*RSA_blocksize; // scaling from one to the other
        byte[] encrypted = new byte[outputLength];
        int numBlocksInput = outputLength/RSA_blocksize;
        for (int i = 0; i < numBlocksInput; i++)
            {
            cipher.doFinal(padded, i*usable_blocksize, usable_blocksize, encrypted, i*RSA_blocksize); // different blocksizes for input and output
            }
        return encrypted;
        }

private byte[] rsa_decrypt_blocks(AlgorithmSpec algorithmSpec, PublicKey senderPublicKey, byte[] encryptedData)
        throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
    Cipher cipher = cryptoFactory.getCipherFromCipherSpec(algorithmSpec);

    final int RSA_blocksize = algorithmSpec.getCipherBlockSize();
    int usable_blocksize = algorithmSpec.getUsableBlockSize();

    if (encryptedData.length%RSA_blocksize != 0)
        {
        throw new IllegalArgumentException("input length doesn't fit with key size");
        }
    int numBlocks = encryptedData.length/RSA_blocksize; // because of previous check, this is clean
    // int decryptedLength = encryptedData.length; // same
    byte[] decrypted = new byte[numBlocks*usable_blocksize];

    // decrypt
    cipher.init(Cipher.DECRYPT_MODE, senderPublicKey, rng);
    // we're to process the blocks ourselves.
    int i = numBlocks;
    int inputOffset = 0;
    int outputOffset = 0;

    // if memory saving is a big issue, it would be an option to write directly to "decrypted" output array and
    // shift the contents in case the offsetCorrection != 0 by that amount, placing leading 00 bytes "in front".
    byte[] blockBuffer = new byte[usable_blocksize+1];
    while (i > 0)
        {
        int numBytesWritten = cipher.doFinal(encryptedData, inputOffset, RSA_blocksize, blockBuffer, 0);
        // if topmost digits are 00, the BC RSA implementation simply omits them, instead of writing leading zeroes.
        int offsetCorrection = (usable_blocksize - numBytesWritten);
        // this correction inserts the missing zero bytes by using a temporary buffer and shifting the copy, if needed.
        System.arraycopy(blockBuffer, 0, decrypted, outputOffset+offsetCorrection, numBytesWritten);
        inputOffset += RSA_blocksize;
        outputOffset += usable_blocksize; // should append steady, not skip the "missing" 00 byte.
        i--;
        }
    return decrypted;
    }
}