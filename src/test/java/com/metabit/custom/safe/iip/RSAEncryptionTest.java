package com.metabit.custom.safe.iip;


import com.metabit.custom.safe.iip.shared.*;
import com.metabit.custom.safe.safeseal.impl.CryptoFactoryImpl;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.metabit.support.format.HexDump;

import javax.crypto.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;

@Slf4j
public class RSAEncryptionTest
{
    private static Provider      securityProvider;
    private static SecureRandom  rng;
    private CryptoFactory cf;
    private        KeyPair       senderKeypair;
    private        AlgorithmSpec spec;

    @BeforeAll
    static void setUp()
        {
        if (Security.getProvider("BC")==null)
            Security.addProvider(new BouncyCastleProvider());
        // now we need the cipher, right?
        securityProvider = Security.getProvider("BC");
        rng = new SecureRandom();
        }

    @BeforeEach
    void init() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
        {
        cf = new CryptoFactoryImpl();
        spec = AlgorithmSpecCollection.RSA2048;

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", securityProvider);
        final int keysize = spec.getKeySizeInBit();

        kpg.initialize(new RSAKeyGenParameterSpec(keysize, RSAKeyGenParameterSpec.F4));
        senderKeypair = kpg.generateKeyPair();
        }

    @Test
    void testKeyPairGeneration() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
        {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", securityProvider);
        kpg.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)); // 2048 bit key size

        KeyPair keypair = kpg.generateKeyPair();

        kpg.initialize(new RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4)); // 1024 bit key size
        KeyPair keypair2 = kpg.generateKeyPair();

        log.info(keypair2.getPublic().getFormat());
        log.info(keypair2.getPrivate().getFormat());
        log.info(keypair2.getPublic().getAlgorithm());
        }


    /*
    TIL: Line 50 in org.bouncycastle.crypto.engines.RSACoreEngine explicitly checks against provided size **+1**.
         so the data must be always < RSA_blocksize, or <=(RSA_blocksize-1).
     */
    @Test
    void testRSANoPaddingForCorrectness() throws
                                          NoSuchAlgorithmException,
                                          InvalidAlgorithmParameterException,
                                          NoSuchPaddingException,
                                          InvalidKeyException,
                                          IllegalBlockSizeException,
                                          BadPaddingException, ShortBufferException
        {
        final int keysize = 2048;
        final int RSA_blocksize = keysize/8; // for RSA, keysize in byte is the block size.
        final int blocksize = RSA_blocksize-1; // RSACoreEngine explicitly prevents us from using full size, even with NoPadding.

        SecureRandom rng = new SecureRandom();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(new RSAKeyGenParameterSpec(keysize, RSAKeyGenParameterSpec.F4));
        KeyPair keypair = kpg.generateKeyPair();

        byte[] singleBlock = new byte[blocksize];
        rng.nextBytes(singleBlock); // fill block with random data
        log.info("blocksize = "+blocksize);

        Cipher rsaEncrypt = Cipher.getInstance("RSA/ECB/NoPadding", securityProvider);
        rsaEncrypt.init(Cipher.ENCRYPT_MODE, keypair.getPrivate(), rng);

        byte[] encrypted1 = rsaEncrypt.doFinal(singleBlock); // works
        byte[] encrypted2 = rsaEncrypt.doFinal(singleBlock, 0, blocksize); // works
        byte[] encrypted3 = new byte[RSA_blocksize];
        rsaEncrypt.doFinal(singleBlock, 0, blocksize, encrypted3, 0); // works
//        byte[] encrypted4 = new byte[RSA_blocksize+10];
//        rsaEncrypt.doFinal(singleBlock,0,blocksize,encrypted4,10); // works

        // so, with single block, encryption works OK.
        // let's check decryption for these blocks:
        Cipher rssDecrypt = Cipher.getInstance("RSA/ECB/NoPadding", securityProvider);
        rssDecrypt.init(Cipher.DECRYPT_MODE, keypair.getPublic(), rng);

        byte[] decrypted1 = rssDecrypt.doFinal(encrypted1);
        Assertions.assertArrayEquals(singleBlock, decrypted1);

        byte[] decrypted2 = rssDecrypt.doFinal(encrypted2);
        Assertions.assertArrayEquals(singleBlock, decrypted2);

        byte[] decrypted3 = rssDecrypt.doFinal(encrypted3);
        Assertions.assertArrayEquals(singleBlock, decrypted3);

        Assertions.assertArrayEquals(encrypted1, encrypted2);
        Assertions.assertArrayEquals(encrypted2, encrypted3);

        // so this is the tricky bit: output offsets
        // Assertions.assertArrayEquals(encrypted3,encrypted4 from offset 10);

        for (int i = 0; i<20; i++)
            {
            byte[] encrypted4 = new byte[RSA_blocksize+i];
            byte[] decrypted4 = new byte[singleBlock.length];

            rsaEncrypt.doFinal(singleBlock, 0, blocksize, encrypted4, i); // NB: encryption uses input-blocksize (because plaintext is its input)
            rssDecrypt.doFinal(encrypted4, i, RSA_blocksize, decrypted4, 0); // NB: decryption uses RSA_blocksize! (because RSA is its input)
            Assertions.assertArrayEquals(singleBlock, decrypted4);
            }


        byte[] threeBlocks = new byte[blocksize*3];
        rng.nextBytes(threeBlocks); // fill blocks with random data
        assert (threeBlocks.length%blocksize==0);
        byte[] encrypted5 = new byte[threeBlocks.length]; // output size like input size.

        rsaEncrypt.doFinal(threeBlocks, 0, blocksize, encrypted5, 0);
        int offset = 1*blocksize;
        rsaEncrypt.doFinal(threeBlocks, offset, blocksize, encrypted5, offset);

        return;
        }


    /**
     * this test performs the implementation steps "manually", to aid in debugging.
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws ShortBufferException
     */
    @Test
    void performRSAmanually() throws
                             NoSuchAlgorithmException,
                             InvalidAlgorithmParameterException,
                             NoSuchPaddingException,
                             InvalidKeyException,
                             IllegalBlockSizeException,
                             BadPaddingException,
                             ShortBufferException
        {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", securityProvider);
        final int keysize = 2048;
        final int RSA_blocksize = keysize/8; // for RSA, keysize in byte is the block size.
        final int RSA_padding_size = 1; // SURPRISE! Even NoPadding requires 1 byte with RSA.
        final int usable_blocksize = RSA_blocksize-RSA_padding_size; // effective blocks.

        kpg.initialize(new RSAKeyGenParameterSpec(keysize, RSAKeyGenParameterSpec.F4));
        KeyPair senderKeypair = kpg.generateKeyPair();

        InterleavedIntegrityPadding_V1_0 integrityPaddingInstance = new InterleavedIntegrityPadding_V1_0(usable_blocksize);

        byte[] data = "dummy data".getBytes(StandardCharsets.UTF_8);
        // padding
        byte[] padded = integrityPaddingInstance.performPaddingWithAllocation(data);
        log.info("unencrypted padded size = "+padded.length);
        Assertions.assertEquals(padded.length%usable_blocksize, 0); // single block?// encrypt
        log.info("IIP blocksize = "+usable_blocksize);
        log.info("number of blocks =  "+(padded.length/usable_blocksize));

        // encrypt
        Cipher rsa = Cipher.getInstance("RSA/ECB/NoPadding", securityProvider);
        rsa.init(Cipher.ENCRYPT_MODE, senderKeypair.getPrivate(), rng);
        // rsa will support single blocks only, so we have to split ourselves.
        log.info("padded\n"+HexDump.bytesToHexString(padded, " ", 64));
        log.info("padded size   = "+padded.length);
        log.info("RSA blocksize = "+RSA_blocksize);

        int inputLength = padded.length;
        int outputLength = (inputLength/usable_blocksize)*RSA_blocksize; // scaling from one to the other
        byte[] encrypted = new byte[outputLength];
        int numBlocksInput = outputLength/RSA_blocksize;
        for (int i = 0; i<numBlocksInput; i++)
            {
            rsa.doFinal(padded, i*usable_blocksize, usable_blocksize, encrypted, i*RSA_blocksize); // different blocksizes. Details matter.
            }
        log.info("encrypted size = "+encrypted.length);
        // ----
        // log.info("encrypted\n" + HexDump.bytesToHexString(encrypted, " ", 64));
        log.info("encrypted\n"+Base64.toBase64String(encrypted));


        //---------------------------------------------------
        // longer test will wrap here in transport format etc, but this is the test for RSA.
        // now perform decryption.
        // what is known?
        // -- the overall size of encrypted data
        // -- the cipher block size RSA_blocksize.
        // -- also, if we need it, usable_blocksize
        Assertions.assertTrue(outputLength%RSA_blocksize==0);
        int decryptedLength = outputLength; // same
        int numBlocks = outputLength/RSA_blocksize;
        byte[] decrypted = new byte[numBlocks*usable_blocksize];
        byte[] decrypted2 = new byte[numBlocks*usable_blocksize];

        Cipher rsa2 = Cipher.getInstance("RSA/ECB/NoPadding", securityProvider);
        rsa2.init(Cipher.DECRYPT_MODE, senderKeypair.getPublic(), rng);

        // RSA decryption needs to handle different blocksizes "inside" and "outside".
        // this is the more readable form; permanent implementation will use addition/subtraction.
        for (int i = 0; i<numBlocks; i++) // here, RSA_blocksize, not the usable_blocksize
            {
            int inputOffset = i*RSA_blocksize;
            int outputOffset = i*usable_blocksize;
            rsa2.doFinal(encrypted, inputOffset, RSA_blocksize, decrypted2, outputOffset);
            }


        int i = numBlocks;
        int inputOffset = 0;
        int outputOffset = 0;
        while (i>0)
            {
            rsa2.doFinal(encrypted, inputOffset, RSA_blocksize, decrypted, outputOffset);
            inputOffset += RSA_blocksize;
            outputOffset += usable_blocksize;
            i--;
            }

        Assertions.assertArrayEquals(decrypted, decrypted2);
        Assertions.assertArrayEquals(padded, decrypted2);
        return;
        }


/* test to show the difference between BC and Oracle/Sun
    @ParameterizedTest(name = "{index} - test RSAIIP-class with security provider {0}")
    @ValueSource(strings = {"BC", "SunJCE"})
    void testSecurityProviders(final String securityProviderName) throws
                                                                  NoSuchAlgorithmException,
                                                                  InvalidAlgorithmParameterException,
                                                                  NoSuchPaddingException,
                                                                  NoSuchProviderException,
                                                                  InvalidKeyException,
                                                                  IllegalBlockSizeException,
                                                                  ShortBufferException,
                                                                  BadPaddingException, InvalidKeySpecException
        {
        CryptoFactory cfLocal = new CryptoFactory(Security.getProvider(securityProviderName));


        RSAWithIntegrityPadding rsawiip = new RSAWithIntegrityPadding(cfLocal, spec);
        byte[] testInput = "this is a test.".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = rsawiip.padEncryptAndPackage(testInput, null, senderKeypair.getPrivate(), null);

        byte[] decrypted = rsawiip.decryptAndVerify(encrypted, senderKeypair.getPublic(), null, null, null);

        Assertions.assertArrayEquals(testInput, decrypted);
        return;
        }
    */


    //@TODO parameterize this test
    @ParameterizedTest(name = "{index} - test RSAIIP-class with keysize {0}")
    @ValueSource(ints = {1024,2048,4096})
    void testCombinedRSAIIPclass(final Integer keySize) throws
                                                                    NoSuchAlgorithmException,
                                                                    InvalidAlgorithmParameterException,
                                                                    NoSuchPaddingException,
                                                                    NoSuchProviderException,
                                                                    InvalidKeyException,
                                                                    IllegalBlockSizeException,
                                                                    ShortBufferException,
                                                                    BadPaddingException, InvalidKeySpecException
        {
        switch (keySize)
            {
            case 2048: spec = AlgorithmSpecCollection.RSA2048; break;
            case 4096: spec = AlgorithmSpecCollection.RSA4096; break;
            default:
                System.err.println("keysize " + keySize + " not supported");
                return;
            }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", securityProvider);
        Assertions.assertEquals(keySize, spec.getKeySizeInBit());
        kpg.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4));
        KeyPair localKeypair = kpg.generateKeyPair();

        RSAWithIntegrityPadding rsawiip = new RSAWithIntegrityPadding(cf, spec);
        byte[] testInput = "this is a test.".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = rsawiip.padEncryptAndPackage(testInput, (PublicKey) null, localKeypair.getPrivate(), null);

        byte[] decrypted = rsawiip.decryptAndVerify(encrypted, localKeypair.getPublic(), null, null, null);

        Assertions.assertArrayEquals(testInput, decrypted);
        return;
        }



    @Test
    void useWithCipherSpec() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException
        {
        AlgorithmSpec specRSA2048 = new AlgorithmSpec(SharedConstants.OID_RSA_ECB, "RSA/ECB/NoPadding", AlgorithmSpec.Type.CIPHER, true, 2048, 256, 1); // internal test constructor, not public
        // strange enough, this works in above environment?!
        Cipher cipher = cf.getCipherFromCipherSpec(specRSA2048); // which *really* should reflect "RSA/ECB/NoPadding"
        Cipher plainRSA2k = Cipher.getInstance(specRSA2048.getOID().toString());
        //@TODO
        }

}
