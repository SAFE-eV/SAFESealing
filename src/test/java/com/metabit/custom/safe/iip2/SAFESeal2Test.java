package com.metabit.custom.safe.iip2;

import com.metabit.custom.safe.iip.shared.CryptoFactory;
import com.metabit.custom.safe.iip.shared.SharedTestingCode;
import com.metabit.custom.safe.safeseal.impl.CryptoFactoryImpl;
import org.junit.jupiter.api.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.nio.file.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

import static java.nio.file.StandardOpenOption.*;

class SAFESeal2Test
{
    private static CryptoFactory cryptoFactory;
    private        KeyPair       keyPair;

    @BeforeAll
    static void overallInit()
        {
        cryptoFactory = new CryptoFactoryImpl();
        }

    @BeforeEach
    void init()
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException
        {
        keyPair = SharedTestingCode.generateRSAKeyPair(2048);
        }


    @Test
    void loopback1()
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, ShortBufferException,
            InvalidKeySpecException, BadPaddingException, IOException
        {
        byte[] testPayload = "this is a simple test".getBytes();
        SAFESeal2 handleInstance = new SAFESeal2(cryptoFactory, 2, 0);
        byte[] sealed = handleInstance.seal(testPayload, keyPair.getPrivate(), null, 0L);
        Path tempfile = Paths.get("/tmp/safesealing2.der");
        Files.write(tempfile, sealed, CREATE);

        byte[] revealed = handleInstance.reveal(sealed, null, keyPair.getPublic());

        Assertions.assertArrayEquals(testPayload, revealed);
        }


    @RepeatedTest(100)
    void testRandomContents()
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, ShortBufferException,
            InvalidKeySpecException, BadPaddingException, IOException
        {
        Random simpleRandom = new Random();
        int payloadSize = simpleRandom.nextInt(65537);
        byte[] testPayload = new byte[payloadSize];
        simpleRandom.nextBytes(testPayload);

        SAFESeal2 handleInstance = new SAFESeal2(cryptoFactory, 2, 0);

        // randomly activate compression, to cover that as well
        handleInstance.setCompressionMode(simpleRandom.nextBoolean());

        byte[] sealed = handleInstance.seal(testPayload, keyPair.getPrivate(), null, 0L);
        byte[] revealed = handleInstance.reveal(sealed, null, keyPair.getPublic());

        Assertions.assertArrayEquals(testPayload, revealed);
        }

    @Test
    void testCornercaseEmptyInput()
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, ShortBufferException,
            InvalidKeySpecException, BadPaddingException, IOException
        {
        byte[] testPayload = "".getBytes();
        SAFESeal2 handleInstance = new SAFESeal2(cryptoFactory, 2, 0);
        byte[] sealed = handleInstance.seal(testPayload, keyPair.getPrivate(), null, 0L);
        byte[] revealed = handleInstance.reveal(sealed, null, keyPair.getPublic());
        Assertions.assertArrayEquals(testPayload, revealed);
        }
}