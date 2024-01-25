package com.metabit.custom.safe.iip;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class SharedTestMethods
{
    public static SecretKey generateKey(int keySizeBits) throws NoSuchAlgorithmException
        {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keySizeBits);
        SecretKey key = keyGenerator.generateKey();
        return key;
        }
    
    public static void flipRandomBit(int testDataSize, Random rng, byte[] encrypted)
        {
        int bitToFlip = rng.nextInt(testDataSize * 8);
        encrypted[bitToFlip >> 3] ^= (1 << (bitToFlip & 7));
        }
    
    public static void flipSpecificBit(int bitToFlip, byte[] encrypted)
        {
        encrypted[bitToFlip >> 3] ^= (1 << (bitToFlip & 7));
        }
    
}
