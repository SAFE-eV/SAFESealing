package com.metabit.custom.safe.iip.shared;

import javax.crypto.*;
import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;

public class SharedTestingCode
{
public static byte[] rsa_decrypt_blocks(CryptoFactory cryptoFactory, SecureRandom rng, final AlgorithmSpec algorithmSpec, final PublicKey senderPublicKey, final byte[] ciphertext)
        throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
    Cipher cipher = cryptoFactory.getCipherFromCipherSpec(algorithmSpec);
    final int RSA_blocksize = algorithmSpec.getCipherBlockSize();
    int usable_blocksize = algorithmSpec.getUsableBlockSize();

    if (ciphertext.length%RSA_blocksize != 0)
        {
        throw new IllegalArgumentException("input length doesn't fit with key size");
        }
    int numBlocks = ciphertext.length/RSA_blocksize; // because of previous check, this is clean
    int decryptedLength = ciphertext.length; // same

    byte[] decrypted = new byte[numBlocks*usable_blocksize];

    // decrypt
    cipher.init(Cipher.DECRYPT_MODE, senderPublicKey, rng);
    // we're to process the blocks ourselves.
    int i = numBlocks;
    int inputOffset = 0;
    int outputOffset = 0;
    while (i > 0)
        {
        cipher.doFinal(ciphertext, inputOffset, RSA_blocksize, decrypted, outputOffset);
        inputOffset += RSA_blocksize;
        outputOffset += usable_blocksize;
        i--;
        }
    return decrypted;
    }

public static byte[] rsa_encrypt_blocks(CryptoFactory cryptoFactory, SecureRandom rng, final AlgorithmSpec algorithmSpec, final PrivateKey senderPrivateKey, final byte[] plaintext)
        throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException,
        InvalidAlgorithmParameterException
    {
    Cipher cipher = cryptoFactory.getCipherFromCipherSpec(algorithmSpec);
    int usable_blocksize = algorithmSpec.getUsableBlockSize();
    int RSA_blocksize = algorithmSpec.getCipherBlockSize();
    cipher.init(Cipher.ENCRYPT_MODE, senderPrivateKey, rng);
    // rsa will support single blocks only, so we have to split ourselves.
    int inputLength = plaintext.length;
    int outputLength = (inputLength/usable_blocksize)*RSA_blocksize; // scaling from one to the other
    byte[] encrypted = new byte[outputLength];
    int numBlocksInput = outputLength/RSA_blocksize;
    for (int i = 0; i < numBlocksInput; i++)
        {
        cipher.doFinal(plaintext, i*usable_blocksize, usable_blocksize, encrypted, i*RSA_blocksize); // different blocksizes. Details matter.
        }
    return encrypted;
    }

public static KeyPair generateRSAKeyPair(int keySize)
        throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
    {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4));
    // kpg.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F0));
    return kpg.generateKeyPair();
    }

    public static SecretKey generateAESKey(int n)
            throws NoSuchAlgorithmException
        {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey key = keyGenerator.generateKey();
        return key;
        }

public enum GuardDataTypes
{ZEROES, ONES, FIVES, AS, RANDOM}

;

public static byte[] generatePadding(int size, final GuardDataTypes type, SecureRandom rng)
    {
    byte[] padding = new byte[size];
    switch (type)
        {
        case ZEROES:
            Arrays.fill(padding, (byte) 0x00);
            break;
        case ONES:
            Arrays.fill(padding, (byte) 0xFF);
            break;
        case FIVES:
            Arrays.fill(padding, (byte) 0x55);
            break;
        case AS:
            Arrays.fill(padding, (byte) 0xAA);
            break;
        case RANDOM:
            rng.nextBytes(padding);
            ;
            break;
        }
    return padding;
    }
}
