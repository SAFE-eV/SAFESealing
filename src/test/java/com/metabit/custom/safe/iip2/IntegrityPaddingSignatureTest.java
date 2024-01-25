package com.metabit.custom.safe.iip2;

import com.metabit.custom.safe.iip.shared.CryptoFactory;
import com.metabit.custom.safe.iip.shared.SharedTestingCode;
import com.metabit.custom.safe.safeseal.impl.CryptoFactoryImpl;
import com.metabit.custom.safe.safeseal.impl.CryptoSettingsStruct;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.*;
import org.metabit.library.misc.util.formatting.HexDump;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.*;
import java.security.*;

class IntegrityPaddingSignatureTest
{
    private static SecureRandom         rng;
    private static CryptoFactory        cf;
    private static CryptoSettingsStruct css;
    private        SecretKey            sk1;
    private        SecretKey            sk2;
    private        SecretKey            sk3;
    private        KeyPair              keyPair;

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


    @Test
    void performSingleRunWithFixedContent()
            throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, ShortBufferException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException,
            InvalidKeyException
        {
        final byte[] plaintext = "Dies ist der Testtext, welchen wir unverändert wiederzufinden erwarten".getBytes(StandardCharsets.UTF_8);
        IntegrityPaddingSignature instance = new IntegrityPaddingSignature(cf, css);

        byte[] encrypted = instance.performEncryption(plaintext, keyPair.getPrivate(), sk1, sk2, sk3);
        byte[] decrypted = instance.performDecryptionAndValidation(encrypted, keyPair.getPublic(), sk1, sk2, sk3);

        Assertions.assertArrayEquals(plaintext, decrypted);
        }

    @Test
    void printMagicID()
        {
        BigInteger bigIntMagicID = new BigInteger(IntegrityPaddingSignature.MAGIC_ID);
        System.out.print("magic ID in hex    : ");
        System.out.println(HexDump.bytesToHexString(IntegrityPaddingSignature.MAGIC_ID, " ", 32));
        System.out.println("magic ID as Integer: "+bigIntMagicID);
        }

    @Test
    void performSingleRunWithLargerFixedContent()
            throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, ShortBufferException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException,
            InvalidKeyException
        {
        final byte[] plaintext = ("Dies ist der Testtext, welchen wir unverändert wiederzufinden erwarten. "+
                "Wir verlängern diesen Text auf eine Größe, welche die Verwendung mehrerer Blocks "+
                "provoziert, um den diesbezüglichen Ablauf ebenfalls testen zu können. "+
                "Andere Tests werden mit automatisch erzeugten Daten verschiedener Größe "+
                "durchgeführt, um eine größere Bandbreite an Möglichkeiten abzudecken."+
                "").getBytes(StandardCharsets.UTF_8);
        IntegrityPaddingSignature instance = new IntegrityPaddingSignature(cf, css);
        byte[] encrypted = instance.performEncryption(plaintext, keyPair.getPrivate(), sk1, sk2, sk3);
        byte[] decrypted = instance.performDecryptionAndValidation(encrypted, keyPair.getPublic(), sk1, sk2, sk3);
        Assertions.assertArrayEquals(plaintext, decrypted);
        }


    @Test
    void performSingleRunWithEmptyContent()
            throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, ShortBufferException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException,
            InvalidKeyException
        {
        final byte[] plaintext = "".getBytes(StandardCharsets.UTF_8);
        IntegrityPaddingSignature instance = new IntegrityPaddingSignature(cf, css);

        byte[] encrypted = instance.performEncryption(plaintext, keyPair.getPrivate(), sk1, sk2, sk3);
        byte[] decrypted = instance.performDecryptionAndValidation(encrypted, keyPair.getPublic(), sk1, sk2, sk3);
        Assertions.assertArrayEquals(plaintext, decrypted);
        }

    @RepeatedTest(100)
    void performSingleRunWithRandomContent()
            throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, ShortBufferException, NoSuchAlgorithmException, BadPaddingException, NoSuchProviderException,
            InvalidKeyException
        {
        int size = rng.nextInt(10000);
        byte[] plaintext = new byte[size];
        rng.nextBytes(plaintext);

        IntegrityPaddingSignature instance = new IntegrityPaddingSignature(cf, css);
        byte[] encrypted = instance.performEncryption(plaintext, keyPair.getPrivate(), sk1, sk2, sk3);
        byte[] decrypted = instance.performDecryptionAndValidation(encrypted, keyPair.getPublic(), sk1, sk2, sk3);
        Assertions.assertArrayEquals(plaintext, decrypted);
        }

}
//___EOF___
