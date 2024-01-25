package com.metabit.custom.safe.iip;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

public class RSAEngineTest
{
    @Test
    public void testRSAMSBhandling()
        {
        SecureRandom random = new SecureRandom();
        // RSACoreEngine is not exported, we have to use the facade.
        RSAKeyPairGenerator pGen = new RSAKeyPairGenerator();
        pGen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x11), random, 1024, 100));
        AsymmetricCipherKeyPair kp = pGen.generateKeyPair();
        RSAKeyParameters rsak = (RSAKeyParameters) kp.getPrivate();
        CipherParameters rsa2048Param = rsak;


        RSAEngine rsaEngine = new RSAEngine();
        rsaEngine.init(true, kp.getPrivate());

        System.out.println("RSA bits   : "+rsak.getModulus().bitLength()); // this is how you get the key size for RSA...!
        System.out.println("input  size: "+rsaEngine.getInputBlockSize());
        System.out.println("output size: "+rsaEngine.getOutputBlockSize());

        int inputSize = rsaEngine.getInputBlockSize();
        byte[] input = new byte[inputSize];
        random.nextBytes(input);

        byte[] encrypted = rsaEngine.processBlock(input, 0, input.length);
        Assertions.assertEquals(encrypted.length, rsaEngine.getOutputBlockSize());

        // using private key for input on decryption? should work if internal logic is good.
        // rsaEngine.init(false, kp.getPublic());
        rsaEngine.init(false, kp.getPublic()); // private/public determines the lengths.

        byte[] decrypted = rsaEngine.processBlock(encrypted, 0, encrypted.length);

        Assertions.assertArrayEquals(input, decrypted);
        }

    @Test
    public void defaultJRERSAlimitations()
            throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
        {
        // OracleUcrypto  has RSA-ECB/NoPadding, but is available only in Oracle JDK.
        // PKCS11 usually has, but depending on the local PKCS11 library.
        // SunPCSC may too, depending on the HSE/SmartCard local hardware setup uses.
        // with BC, we're safe.

        int keysize = 2048;
        int inputBlocksize = (keysize/8); // precise size required for sun.security.rsa.NativeRSACore: no more, no less!
        SecureRandom random = new SecureRandom();

        // standard java JRE JCE
        Cipher rsa = Cipher.getInstance("RSA/ECB/NoPadding"); // this works as expected, with the -1 BC RSA workaround.
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // parameter 2
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // input buffer filled with a constant value
        byte[] input = new byte[inputBlocksize];
        Arrays.fill(input, (byte) 0x55);

        // first test: let's see whether this works unmodified
        forwardBackwardCompare(rsa, keyPair, input);

        // now for our tests.
        input[input.length-1] = 0x00;
        forwardBackwardCompare(rsa, keyPair, input);

        input[input.length-1] = (byte) 0xFF;
        forwardBackwardCompare(rsa, keyPair, input);

        input[0] = (byte) 0x7F;
        forwardBackwardCompare(rsa, keyPair, input);

        input[0] = (byte) 0x80;
        forwardBackwardCompare(rsa, keyPair, input);

        // provokes "javax.crypto.BadPaddingException: Message is larger than modulus"
        /*
            {
            input[0] = (byte) 0xFF;
            forwardBackwardCompare(rsa, keyPair, input);
            }
*/

        // the output size shrinks, depending on library!
        input[0] = 0;
        forwardBackwardCompare(rsa, keyPair, input);

        input[1] = 0;
        forwardBackwardCompare(rsa, keyPair, input);

        }

    // @Test yes, RSA fails here as known :(
    public void implementationsOmittingLeadingZeroBytes()
            throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
        {
        Provider securityProvider = Security.getProvider("BC");
        if (securityProvider == null)
            {
            securityProvider = new BouncyCastleProvider();
            Security.addProvider(securityProvider);
            }

        int keysize = 2048;
        int inputBlocksize = (keysize/8); // precise size required for sun.security.rsa.NativeRSACore: no more, no less!
        SecureRandom random = new SecureRandom();

        // standard java JRE JCE
        String bcProvider;
        Cipher rsa = Cipher.getInstance("RSA/ECB/NoPadding", securityProvider); // this works as expected, with the -1 BC RSA workaround.
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", securityProvider);
        keyPairGenerator.initialize(2048); // parameter 2
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // input buffer filled with a constant value
        byte[] input = new byte[inputBlocksize-1];
        Arrays.fill(input, (byte) 0x55);

        // first test: let's see whether this works unmodified
        forwardBackwardCompare(rsa, keyPair, input);

        // now for our tests.
        input[input.length-1] = 0x00;
        forwardBackwardCompare(rsa, keyPair, input);

        input[input.length-1] = (byte) 0xFF;
        forwardBackwardCompare(rsa, keyPair, input);

        input[0] = (byte) 0x7F;
        forwardBackwardCompare(rsa, keyPair, input);

        input[0] = (byte) 0x80;
        forwardBackwardCompare(rsa, keyPair, input);

        // provokes "javax.crypto.BadPaddingException: Message is larger than modulus"
        // input[0] = (byte) 0xFF;
        // forwardBackwardCompare(rsa, keyPair, input);

        // with BC, the output size shrinks, depending on library!
        input[0] = 0;
//         forwardBackwardCompare(rsa, keyPair, input);
        input[1] = 0;
        input[2] = 0;
        input[3] = 0;
        // forwardBackwardCompare(rsa, keyPair, input);
        rsa.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
        byte[] encrypted = rsa.doFinal(input);
        rsa.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
        byte[] decrypted = rsa.doFinal(encrypted);
        Assertions.assertArrayEquals(input, decrypted);
        }


    private static void forwardBackwardCompare(Cipher rsa, KeyPair keyPair, byte[] input)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException
        {
        rsa.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
        byte[] encrypted = rsa.doFinal(input);
        rsa.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
        byte[] decrypted = rsa.doFinal(encrypted);
        Assertions.assertArrayEquals(input, decrypted);
        }

    // @Test here, too, RSA implementations are tricky.
    public void testFirstOrLastBytes()
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException
        {
        Provider securityProvider = Security.getProvider("BC");
        if (securityProvider == null)
            {
            securityProvider = new BouncyCastleProvider();
            Security.addProvider(securityProvider);
            }

        SecureRandom random = new SecureRandom();

        // BC crypto
        // RSACoreEngine is not exported, we have to use the facade.
        RSAKeyPairGenerator pGen = new RSAKeyPairGenerator();
        pGen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x11), random, 1024, 100));
        AsymmetricCipherKeyPair kp = pGen.generateKeyPair();
        RSAKeyParameters rsak = (RSAKeyParameters) kp.getPrivate();
        CipherParameters rsa2048Param = rsak;

        RSAEngine rsaEngine = new RSAEngine();
        rsaEngine.init(true, kp.getPrivate());

        // JRE crypto -- convert BC-generated key to JRE
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec privKS = new RSAPrivateKeySpec(((RSAKeyParameters) kp.getPrivate()).getModulus(), ((RSAKeyParameters) kp.getPrivate()).getExponent());
        RSAPublicKeySpec pubKS = new RSAPublicKeySpec(((RSAKeyParameters) kp.getPublic()).getModulus(), ((RSAKeyParameters) kp.getPublic()).getExponent());
        PrivateKey priv = factory.generatePrivate(privKS);
        PublicKey pub = factory.generatePublic(pubKS);
        Cipher wrappedRSA = Cipher.getInstance("RSA/ECB/NoPadding", "BC"); // this works as expected, with the -1 BC RSA workaround.
        wrappedRSA.init(Cipher.ENCRYPT_MODE, priv);

        System.out.println("RSA bits   : "+rsak.getModulus().bitLength()); // this is how you get the key size for RSA...!
        System.out.println("input  size: "+rsaEngine.getInputBlockSize());
        System.out.println("output size: "+rsaEngine.getOutputBlockSize());


        int inputSize = rsaEngine.getInputBlockSize();
        byte[] input = new byte[inputSize];
        random.nextBytes(input);

        byte[] encrypted;
        byte[] encrypted2;


        for (int i = 0; i < 256; i++)
            {
            input[input.length-1] = (byte) i;
            try
                {
                encrypted = rsaEngine.processBlock(input, 0, input.length);
                encrypted2 = wrappedRSA.doFinal(input, 0, input.length);
                Assertions.assertEquals(encrypted.length, rsaEngine.getOutputBlockSize());
                Assertions.assertEquals(encrypted.length, rsaEngine.getOutputBlockSize());
                }
            catch (DataLengthException ex)
                {
                System.out.println("RSA fails with larger input size and last+1-1 byte having value "+i);
                }
            }
        for (int i = 0; i < 256; i++)
            {
            input[input.length-2] = (byte) i;
            try
                {
                encrypted = rsaEngine.processBlock(input, 0, input.length);
                encrypted2 = wrappedRSA.doFinal(input, 0, input.length);
                Assertions.assertEquals(encrypted.length, rsaEngine.getOutputBlockSize());
                Assertions.assertEquals(encrypted.length, rsaEngine.getOutputBlockSize());
                }
            catch (DataLengthException ex)
                {
                System.out.println("RSA fails with larger input size and last+1-2 byte having value "+i);
                }
            }

        for (int i = 0; i < 256; i++)
            {
            input[0] = (byte) i;
            try
                {
                encrypted = rsaEngine.processBlock(input, 0, input.length);
                encrypted2 = wrappedRSA.doFinal(input, 0, input.length);
                Assertions.assertEquals(encrypted.length, rsaEngine.getOutputBlockSize());
                Assertions.assertEquals(encrypted.length, rsaEngine.getOutputBlockSize());
                }
            catch (DataLengthException ex)
                {
                System.out.println("RSA fails with larger input size and first byte having value "+i);
                }
            }


        for (int i = 0; i < 256; i++)
            {
            input[0] = (byte) i;
            try
                {
/*
                encrypted = rsaEngine.processBlock(input, 0, input.length);
                rsaEngine.init();
                byte[] decrypted = rsaEngine.processBlock(encrypted, 0, encrypted.length);
                Assertions.assertArrayEquals(input, decrypted);
*/

                wrappedRSA.init(Cipher.ENCRYPT_MODE, priv);
                encrypted2 = wrappedRSA.doFinal(input, 0, input.length);
                wrappedRSA.init(Cipher.DECRYPT_MODE, pub);
                byte[] decrypted2 = wrappedRSA.doFinal(encrypted2, 0, encrypted2.length);
                Assertions.assertArrayEquals(input, decrypted2);
                }
            catch (DataLengthException ex)
                {
                System.out.println("RSA fails with larger input size and first byte having value "+i);
                }
            }


        // using private key for input on decryption? should work if internal logic is good.
        // rsaEngine.init(false, kp.getPublic());
        rsaEngine.init(false, kp.getPublic()); // private/public determines the lengths.

        }


}

// Cipher.RSA/RAW