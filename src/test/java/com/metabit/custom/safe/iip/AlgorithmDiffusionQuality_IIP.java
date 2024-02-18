package com.metabit.custom.safe.iip;

import com.metabit.custom.safe.iip.shared.AlgorithmSpec;
import com.metabit.custom.safe.iip.shared.SharedTestingCode;
import com.metabit.custom.safe.safeseal.impl.CryptoFactoryImpl;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.metabit.library.misc.util.stats.SimpleIntegerStatsCounter;
import com.metabit.platform.java.supplymissing.ByteArrayOperations;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static com.metabit.custom.safe.iip.shared.AlgorithmSpecCollection.RSA1024;
import static com.metabit.custom.safe.iip.shared.AlgorithmSpecCollection.RSA2048;
import static com.metabit.custom.safe.iip.shared.SharedTestingCode.generateRSAKeyPair;
import static com.metabit.custom.safe.iip.shared.SharedTestingCode.rsa_encrypt_blocks;


/**
 * the goal of this class is to calculate statistical values of algorithm diffusion qualities,
 * specifically understanding how often the first four bytes = 32 bit of a block is affected.
 *
 * @see {task MC-117}
 */

@Slf4j
@EnabledIfEnvironmentVariable(named = "statistics", matches = "true")
// run only when specifically activated, not on maven test phase during regular builds
public class AlgorithmDiffusionQuality_IIP
{
// inner class for collecting and writing out the results
class ADQData
{
    private final int    usableBits;
    private final String algorithmName;
    private final int    algorithmBlockSizeInBit;
    int                         numKeyPairsTested;
    int[]                       testsPerformed;
    int[]                       changesDetected;
    int[]                       changesNotDetected;
    SimpleIntegerStatsCounter[] hammingDistances;

    ADQData(AlgorithmSpec algorithmSpec)
        {
        this.algorithmName = algorithmSpec.getName();
        this.algorithmBlockSizeInBit = algorithmSpec.getCipherBlockSize()*8;
        this.usableBits = algorithmSpec.getUsableBlockSize()*8;
        this.numKeyPairsTested = 0;
        testsPerformed = new int[usableBits];
        changesDetected = new int[usableBits];
        changesNotDetected = new int[usableBits];
        hammingDistances = new SimpleIntegerStatsCounter[usableBits]; // without entries. We do this so the minimal hamming distance is not fixed to 0.
        }

    public void print(PrintStream out)
        {
        out.println(algorithmName+" "+algorithmBlockSizeInBit+" bit");
        out.println(numKeyPairsTested+" keys tested");
        out.println(); // empty line before table is mandatory in MarkDown
        // start table here with MD table header
        out.println("| # | tests | detected | failed | diffcount | min | max | mean int | mean |");
        out.println("|--:|---:|---:|---:|--:|--:|--:|--:|----|");
        for (int i = 0; i < usableBits; i++)
            {
            out.print("|");
            out.print(i);
            out.print("|");
            out.print(testsPerformed[i]);
            out.print("|");
            out.print(changesDetected[i]);
            out.print("|");
            out.print(changesNotDetected[i]);
            out.print("|");
            if (hammingDistances[i] != null)
                {
                out.print(hammingDistances[i].getNumberOfValuesCounted());
                out.print("|");
                out.print(hammingDistances[i].getAllTimeMinimum());
                out.print("|");
                out.print(hammingDistances[i].getAllTimeMaximum());
                out.print("|");
                out.print(hammingDistances[i].getArithmeticMean());
                out.print("|");
                out.print(hammingDistances[i].getArithmeticMeanAsDouble());
                out.print("|");
                }
            else
                {
                out.print("|||||");
                }
            out.println();
            }
        }

    public void increaseNumKeyPairsTested() { numKeyPairsTested++; }

    public void increaseTestsPerformed(final int index) { testsPerformed[index]++; }

    public void increaseDetectedTampering(final int offset) { changesDetected[offset]++; }

    public void increaseUndetectedTampering(final int offset) { changesNotDetected[offset]++; }

    public void recordDetectionQuality(final int offset, final int detectedChanges)
        {
        if (this.hammingDistances[offset] == null)
            this.hammingDistances[offset] = new SimpleIntegerStatsCounter(detectedChanges);
        else
            this.hammingDistances[offset].put(detectedChanges);
        return;
        }
}

private static CryptoFactoryImpl cryptoFactory;
private static SecureRandom      rng;


@BeforeAll
static void globalInit()
    {
    cryptoFactory = new CryptoFactoryImpl();
    rng = new SecureRandom();
    }

private static Stream<Arguments> testAlgorithms()
    {
    return Stream.of(
            // Arguments.of(RSA1024, 10000) // yields 10 million samples
            // Arguments.of(RSA1024, 1000000) //
            Arguments.of(RSA2048, 1000)
            // Arguments.of(RSA2048, 10000)
            // Arguments.of(RSA4096, 1000)
    );
    }


@ParameterizedTest
@MethodSource("testAlgorithms")
void diffusionDetectionQualityTest(final AlgorithmSpec algorithmSpec, final int numKeyPairsToTestWith)
        throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException,
        InvalidKeyException, IOException
    {
    ADQData result = new ADQData(algorithmSpec);
    long numberOfTestsPerformed = 0;
    long startingtime = System.currentTimeMillis();

    // generate test data
    byte[] plaintext = new byte[algorithmSpec.getUsableBlockSize()];
    rng.nextBytes(plaintext);
    // generate key paris
    System.out.println("generating "+numKeyPairsToTestWith+" key pairs");
    List<KeyPair> keyPairs = generateKeyPairs(algorithmSpec, numKeyPairsToTestWith);
    System.out.println(keyPairs.size()+" key pairs generated, took "+(System.currentTimeMillis()-startingtime)/1000+" seconds.");

    // outermost loop: repeat test with different keys / key pairs
    for (KeyPair keyPair : keyPairs)
        {
        // encrypt the plaintext
        PrivateKey senderPrivateKey = keyPair.getPrivate();
        PublicKey senderPublicKey = keyPair.getPublic();
        // encrypt the test data
        byte[] ciphertext = rsa_encrypt_blocks(cryptoFactory, rng, algorithmSpec, senderPrivateKey, plaintext);
        int ciphertextLengthInByte = ciphertext.length;
        byte[] tampered = new byte[ciphertextLengthInByte]; // prepare array for modified data

        // test each bit in the encrypted block
        int blocksize = algorithmSpec.getUsableBlockSize()*8; // blocksize in bit
        for (int bitPosition = 0; bitPosition < blocksize; bitPosition++)
            {
            // copy the original unmodified ciphertext
            System.arraycopy(ciphertext, 0, tampered, 0, ciphertextLengthInByte);
            // flip given bit
            tampered[bitPosition/8] ^= (1<<(bitPosition%8));
            // attempt decryption of tampered data
            try
                {
                byte[] decrypted = SharedTestingCode.rsa_decrypt_blocks(cryptoFactory, rng, algorithmSpec, senderPublicKey, tampered);

                // our test here is to check the first 32 bit for change detection.
                int detectedChanges = detectChangesFromPartialArray(plaintext, decrypted, 64);
                if (detectedChanges == 0)
                    {
                    result.increaseUndetectedTampering(bitPosition); // NB: this is a *partial* array we're testing, intentionally.
                    }
                else
                    {
                    result.increaseDetectedTampering(bitPosition); // once for the position; @IMPROVEMENT?change this to a flag?
                    }
                result.increaseTestsPerformed(bitPosition);
                }
            catch (Exception ex)
                {
                result.increaseDetectedTampering(bitPosition);
                result.increaseTestsPerformed(bitPosition);
                }
            numberOfTestsPerformed++;
            // -------------------------- progress and preliminary results ---------
            if (numberOfTestsPerformed%1000 == 0)
                {
                System.out.println(numberOfTestsPerformed+" tests, "+(System.currentTimeMillis()-startingtime)/1000+" seconds.");
                System.out.flush();
                FileOutputStream fos = new FileOutputStream("testresults.md");
                result.print(new PrintStream(fos));
                fos.close();
                }
            } // bit change position loop
        result.increaseNumKeyPairsTested();
        } // key loop
    result.print(System.out);
    FileOutputStream fos = new FileOutputStream("testresults.md");
    result.print(new PrintStream(fos));
    fos.close();
    return;
    }

/**
 * primary algorithm approach: limit our view to first X bits/bytes
 *
 * @param plaintext
 * @param decrypted
 * @param numBytesToCompare
 * @return
 */
private int detectChangesFromPartialArray(byte[] plaintext, byte[] decrypted, int numBytesToCompare)
    {
    // limit our scope to the X first bytes, then check
    return ByteArrayOperations.arrayBitDifferenceCounting(plaintext, 0, decrypted, 0, numBytesToCompare);
    }


//@TODO we need a class that unifies Key and KeyPair here
private static List<KeyPair> generateKeyPairs(AlgorithmSpec algorithmSpec, int numKeyPairsToTestWith)
        throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
    {
    // prepare keypairs to work with
    List<KeyPair> keyPairs = new ArrayList<>(numKeyPairsToTestWith);
    if (algorithmSpec.getName().contains("RSA"))
        {
        for (int i = 0; i < numKeyPairsToTestWith; i++)
            { keyPairs.add(generateRSAKeyPair(algorithmSpec.getKeySizeInBit())); }
        }
    else
        {
        throw new UnsupportedOperationException("algorithm "+algorithmSpec+" key generation not implemented yet");
        }
    return keyPairs;
    }
}
//___EOF___
