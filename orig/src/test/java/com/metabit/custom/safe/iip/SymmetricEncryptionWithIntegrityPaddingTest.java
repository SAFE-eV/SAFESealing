package com.metabit.custom.safe.iip;

import com.metabit.custom.safe.iip.shared.CryptoFactory;
import com.metabit.custom.safe.safeseal.impl.CryptoFactoryImpl;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class SymmetricEncryptionWithIntegrityPaddingTest
{
    // ECB and CBC are suitable modes.

    @Test
    public void testManipulationIsDetectedForAESECB()
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException,
                   BadPaddingException, InvalidAlgorithmParameterException
        {
        CryptoFactory cf = new CryptoFactoryImpl();

        int testDataSize = 80;
        Random rng = new Random();
        byte[] testData = new byte[testDataSize];
        rng.nextBytes(testData);

        Provider bc = new BouncyCastleProvider();
        Cipher symmetricCipher=Cipher.getInstance("AES/ECB/NoPadding", bc);
        SymmetricEncryptionWithIntegrityPadding instance = new SymmetricEncryptionWithIntegrityPadding(symmetricCipher,cf);
        for (int i=0; i<testDataSize*8; i++)
            {
            SecretKey secretKey = SharedTestMethods.generateKey(256);

            final byte[] encrypted = instance.padAndEncrypt(testData,secretKey);
            assertNotNull(encrypted);
            final byte[] iv = instance.getIV(); // valid after encryption
            assertNull(iv); // for ECB, there is no IV needed, so none should be generated
            
            byte[] decrypted = instance.decryptAndCheck(encrypted, secretKey, iv);
// System.out.println(HexDump.bytesToHexString(testData," ",16));
// System.out.println(HexDump.bytesToHexString(decrypted," ",16));
            assertArrayEquals(testData, decrypted);
            
            // flip a single bit in the encrypted data
            SharedTestMethods.flipSpecificBit(i,encrypted);
            // System.out.println(testDataSize + " bytes,  bit#" + i + " in byte " + (i>>3));
            // make sure the check detects the change
            Exception ex = assertThrows(Exception.class, () -> instance.decryptAndCheck(encrypted,secretKey,iv)); // assertThrows() fails if the Exception is *not* thrown.
            // SunJCE throws an "BadPaddingException" which extends GeneralSecurityException, ...
            // BouncyCastle throws a org.bouncycastle.crypto.DataLengthException, which derives from RuntimeException
            // the important bit is that an exception is thrown.
            }
        return;
        }
    
    
    @Test
    public void testManipulationIsDetectedForAESCBC()
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException,
                   BadPaddingException, InvalidAlgorithmParameterException
        {
        CryptoFactory cf = new CryptoFactoryImpl();
        Random rng = new Random();
        for (int testDataSize=1; testDataSize<1024; testDataSize +=3)
            {
            byte[] testData = new byte[testDataSize];
            rng.nextBytes(testData);

            Provider bc = new BouncyCastleProvider();
            Cipher symmetricCipher=Cipher.getInstance("AES/CBC/NoPadding", bc);
            SymmetricEncryptionWithIntegrityPadding instance = new SymmetricEncryptionWithIntegrityPadding(symmetricCipher, cf);
            
            // test every single bit for a change being detected
            for (int i = 0; i < testDataSize * 8; i++)
                {
                SecretKey secretKey = SharedTestMethods.generateKey(256);
    
                final byte[] encrypted = instance.padAndEncrypt(testData, secretKey);
                assertNotNull(encrypted);
                final byte[] iv = instance.getIV(); // valid after encryption
                assertNotNull(iv); // CBC does need an IV
    
                byte[] decrypted = instance.decryptAndCheck(encrypted, secretKey, iv);
                assertArrayEquals(testData, decrypted); // check the roundtrip works as it should
    
                // now check detection of changes - the integrity check doing its job
                // flip a single bit in the encrypted data
                SharedTestMethods.flipSpecificBit(i,encrypted);
                // System.out.println(testDataSize + " bytes,  bit#" + i + " in byte " + (i>>3));
                // make sure the check detects the change
                Exception ex = assertThrows(Exception.class, () -> instance.decryptAndCheck(encrypted, secretKey, iv)); // assertThrows() fails if the Exception is *not* thrown.
                // SunJCE throws an "BadPaddingException" which extends GeneralSecurityException, ...
                // BouncyCastle throws a org.bouncycastle.crypto.DataLengthException, which derives from RuntimeException
                // the important bit is that an exception is thrown.
                }
            }
        return;
        }
}
//___EOF___
