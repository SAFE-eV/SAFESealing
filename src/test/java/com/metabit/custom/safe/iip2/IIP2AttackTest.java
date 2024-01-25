package com.metabit.custom.safe.iip2;

import com.metabit.custom.safe.iip.SharedTestMethods;
import com.metabit.custom.safe.iip.shared.SharedTestingCode;
import com.metabit.custom.safe.safeseal.impl.CryptoFactoryImpl;
import com.metabit.custom.safe.safeseal.impl.CryptoSettingsStruct;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.*;

import javax.crypto.*;
import java.security.*;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
public class IIP2AttackTest
{

    private static SecureRandom         rng;
    private static CryptoFactoryImpl    cf;
    private static CryptoSettingsStruct css;
    private        KeyPair              keyPair;
    private        SecretKey            sk1;
    private        SecretKey            sk2;
    private        SecretKey            sk3;

    @BeforeAll
    static void globalInit()
        {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
        rng = new SecureRandom();
        cf = new CryptoFactoryImpl();
        css = new CryptoSettingsStruct(2, 1);
        }

    @BeforeEach
    void initSingleTest()
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
        {
        keyPair = SharedTestingCode.generateRSAKeyPair(2048);
        sk1 = SharedTestingCode.generateAESKey(1);
        sk2 = SharedTestingCode.generateAESKey(2);
        sk3 = SharedTestingCode.generateAESKey(3);
        }

    @RepeatedTest(10)
    void testAttackDetection()
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IllegalBlockSizeException, ShortBufferException, BadPaddingException,
            InvalidKeyException
        {
        int size = rng.nextInt(10000);
        byte[] plaintext = new byte[size];
        rng.nextBytes(plaintext);
        byte[] testPayload = plaintext;

        IntegrityPaddingSignature instance = new IntegrityPaddingSignature(cf, css);
        byte[] encrypted = instance.performEncryption(plaintext, keyPair.getPrivate(), sk1, sk2, sk3);

        // good case
        byte[] decrypted = instance.performDecryptionAndValidation(encrypted, keyPair.getPublic(), sk1, sk2, sk3);
        Assertions.assertArrayEquals(plaintext, decrypted);

        // now, we intentionally damage the message in a specific placeand see whether that is detected.
        {
        byte[] tmpCopy = Arrays.copyOf(encrypted, encrypted.length); // creates new array and copies elements
        // SharedTestMethods.flipRandomBit(sealed.length, rng, sealed);
        tmpCopy[23] ^= (byte) 0x55; // flip half the bits in this byte
        Exception ex = assertThrows(BadPaddingException.class, ()->instance.performDecryptionAndValidation(tmpCopy, keyPair.getPublic(), sk1, sk2, sk3));
        }

        byte[] sealed = encrypted;

        for (int i = 0; i < sealed.length*8; i++)
            {
            byte[] tmpCopy = Arrays.copyOf(sealed, sealed.length);
            SharedTestMethods.flipSpecificBit(i, tmpCopy);
            try
                {
                byte[] result = instance.performDecryptionAndValidation(tmpCopy, keyPair.getPublic(), sk1, sk2, sk3);
                assertArrayEquals(testPayload, result); // *this* must never fail.

                log.debug("bit # "+i+"\twas inconsequential");
                // payload was intact and could be obtained, even though the wrapper was intentionally damaged
                // there are unused bits in the wrapping, changes in which do not affect the validity of the payload in any way.
                // we can add some additional checks if must be. But the content has never successfully been tampered with.
                }
            catch (BadPaddingException ex) // as expected
                {
                log.trace("bit # "+i+"\tchange detected and rejected");
                }
            catch (DataLengthException ex) // as expected
                {
                log.trace("bit # "+i+"\tchange detected and rejected (RSA)");
                }
            catch (RuntimeException rex)
                {
                log.error("unexpected", rex); // unexpected
                }
            }

        return;
        }

}
